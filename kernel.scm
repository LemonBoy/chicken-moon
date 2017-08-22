(module kernel
  ()
  (import scheme chicken)

(use srfi-1 srfi-18 data-structures
     medea uuid
     (prefix zmq zmq:)
     sha2 hmac string-utils)

(define (string-null? s) (zero? (##sys#size s)))

(define-record context hb-socket shell-socket ctrl-socket iopub-socket hmac-fn)

(define (config->alist file)
  (with-input-from-file file read-json))

(define (time->iso8601 time)
  "YYYY-MM-DDTHH:MM:SS.mmmmmm")

(define (endpoint-address ep cfg)
  (string-append
    (alist-ref 'transport cfg) "://" (alist-ref 'ip cfg)
    ":" (number->string (alist-ref ep cfg))))

(define (punch cfg)
  (apply values
    (map
      (lambda (ep typ)
        (let ((s (zmq:make-socket typ)))
          (zmq:bind-socket s (endpoint-address ep cfg))
          s))
      '(hb_port shell_port control_port iopub_port)
      '(rep xrep xrep pub))))

(define (receive-message/multi socket)
  (let loop ((msg (list (zmq:receive-message* socket))))
    (if (zmq:socket-option socket 'rcvmore)
        (loop (cons (zmq:receive-message* socket) msg))
        (reverse msg))))

(define (send-message/multi socket msg)
  (let loop ((msg msg))
    (unless (null? msg)
      (zmq:send-message socket (car msg) send-more: (pair? (cdr msg)))
      (loop (cdr msg)))))

(define (start-hb-thread! ctx)
  (let* ((hb-socket (context-hb-socket ctx))
         (fd (zmq:socket-fd hb-socket)))
    (thread-start!
      (lambda ()
        (let loop ()
          (thread-wait-for-i/o! fd)
          (zmq:send-message hb-socket (zmq:receive-message* hb-socket))
          (loop))))))

(define-record-type <jmsg>
  (make-jupyter-msg ids header parent meta content)
  jupyter-msg?
  (ids jupyter-msg-ids)
  (header jupyter-msg-header)
  (parent jupyter-msg-parent)
  (meta jupyter-msg-meta)
  (content jupyter-msg-content))

(define (parse-wire-msg ctx msg)
  (let-values (((ids rest) (break! (cut string=? "<IDS|MSG>" <>) msg)))
    ; XXX: Don't hash the raw data if present
    (and-let* ((hmac-fn (context-hmac-fn ctx))
               (sign (hmac-fn (apply string-append (cddr rest)))))
      (unless (string=? (string->hex sign) (second rest))
        (error "corrupted message")))

    (make-jupyter-msg
      ids
      (read-json (third rest))
      (read-json (fourth rest))
      (read-json (fifth rest))
      (read-json (sixth rest)))))

(define (serialize-wire-msg ctx msg)
  (let* ((header  (json->string (jupyter-msg-header msg)))
         (parent  (json->string (jupyter-msg-parent msg)))
         (meta    (json->string (jupyter-msg-meta msg)))
         (content (json->string (jupyter-msg-content msg)))
         (hmac-fn (context-hmac-fn ctx))
         (sign    (if hmac-fn
                    (hmac-fn (string-append header parent meta content))
                    "")))
    `(,@(jupyter-msg-ids msg)
       "<IDS|MSG>"
       ,(string->hex sign)
       ,header ,parent ,meta ,content)))

(define (make-jupyter-msg* reply-to type content)
  (let ((rhdr (jupyter-msg-header reply-to)))
    (make-jupyter-msg
      (jupyter-msg-ids reply-to)
      `((session  . ,(alist-ref 'session rhdr))
        (username . ,(alist-ref 'username rhdr))
        (version  . ,(alist-ref 'version rhdr))
        (date     . ,(time->iso8601 #f))
        (msg_id   . ,(uuid-v4))
        (msg_type . ,type))
      rhdr
      '()
      content)))

(define (call-with-notification ctx msg thunk)
  (let ((iopub-socket (context-iopub-socket ctx)))
    ; notify the frontend we're executing the request
    (send-message/multi iopub-socket
      (serialize-wire-msg ctx
        (make-jupyter-msg* msg "status"
          `((execution_state . "busy")))))
    ; execute the thunk
    (thunk)
    ; notify the frontend we're ready again
    (send-message/multi iopub-socket
      (serialize-wire-msg ctx
        (make-jupyter-msg* msg "status"
          `((execution_state . "idle")))))))

(define (start-shell-thread! ctx)
  (let* ((iopub-socket (context-iopub-socket ctx))
         (shell-socket (context-shell-socket ctx))
         (fd (zmq:socket-fd shell-socket)))
    (thread-start!
      (lambda ()
        (let loop ()
          (thread-wait-for-i/o! fd)

          (let* ((msg (parse-wire-msg ctx (receive-message/multi shell-socket)))
                 (type (alist-ref 'msg_type (jupyter-msg-header msg))))
            (print "recv msg " type)

            (call-with-notification ctx msg
              (lambda ()
                (when (string=? "kernel_info_request" type)
                  (send-message/multi shell-socket
                    (serialize-wire-msg ctx
                      (make-jupyter-msg* msg "kernel_info_reply"
                        `((protocol_version . "5.0")
                          (implementation . "moon")
                          (implementation_version . ,(chicken-version))
                          (banner . "CHICKEN on Jupyter")
                          (language_info .
                                         ((name . "scheme")
                                          (version . "4")
                                          (mimetype . "text/plain")
                                          (file_extension . "scm"))))))))
                (when (string=? "shutdown_request" type)
                  ; simply echo back the message content to let the front-end
                  ; know we're ready to die
                  (send-message/multi shell-socket
                    (serialize-wire-msg ctx
                      (make-jupyter-msg* msg "shutdown_reply"
                        (jupyter-msg-content msg))))
                  (print "goodbye...")
                  (exit))
                (when (string=? "is_complete_request" type)
                  (print "completeness")
                  (send-message/multi shell-socket
                    (serialize-wire-msg ctx
                      (make-jupyter-msg* msg "is_complete_reply"
                        `((status . "unknown"))))))
                (when (string=? "execute_request" type)
                  (print "execute")
                  (send-message/multi shell-socket
                    (serialize-wire-msg ctx
                      (make-jupyter-msg* msg "execute_reply"
                        `((status . "ok")
                          (execution_count . 1))))))))

            (loop)))))))

(define (make-context! config-path)
  (let* ((cfg (config->alist config-path))
         (key (alist-ref 'key cfg)))
    ; bind the sockets
    ; XXX: stdin is missing at the moment
    (let-values (((hb shell ctrl iopub) (punch cfg)))
      (make-context
        hb shell ctrl iopub
        ; generate the hmac routine if the key is given
        ; XXX: parse signature_scheme instead of hardcoding SHA256 as digest fn
        (and (not (string-null? key)) (hmac key (sha256-primitive)))))))

; XXX: handle signals?
(let ((ctx (make-context! (car (command-line-arguments)))))
  (start-hb-thread! ctx)
  (start-shell-thread! ctx)
  (print "loop...")
  (thread-suspend! (current-thread)))
)
