(use srfi-1 srfi-18 data-structures
     medea zmq uuid
     sha2 hmac string-utils)

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
        (let ((s (make-socket typ)))
          (bind-socket s (endpoint-address ep cfg))
          s))
      '(hb_port shell_port)
      '(rep xrep))))

(define (receive-message/multi socket)
  (let loop ((msg (list (receive-message* socket))))
    (if (socket-option socket 'rcvmore)
        (loop (cons (receive-message* socket) msg))
        (reverse msg))))

(define (send-message/multi socket msg)
  (let loop ((msg msg))
    (unless (null? msg)
      (print (pair? (cdr msg)))
      (send-message socket (car msg) #f (pair? (cdr msg)))
      (loop (cdr msg)))))

(define (start-hb-thread! socket)
  (let ((fd (socket-fd socket)))
    (thread-start!
      (lambda ()
        (let loop ()
          (thread-wait-for-i/o! fd)
          (send-message socket (receive-message* socket))
          (loop))))))

(define-record-type <jmsg>
  (make-jupyter-msg ids header parent meta content)
  jupyter-msg?
  (ids jupyter-msg-ids)
  (header jupyter-msg-header)
  (parent jupyter-msg-parent)
  (meta jupyter-msg-meta)
  (content jupyter-msg-content))

(define (parse-wire-msg msg key)
  (let-values (((ids rest) (break! (cut string=? "<IDS|MSG>" <>) msg)))
    (assert (not (null? ids)))

    ; XXX: Don't hash the raw data if present
    (and-let* ((key)
               (sign (hmac-fn (apply string-append (cddr rest)))))
      (unless (string=? (string->hex sign) (second rest))
        (error "corrupted message")))

    (make-jupyter-msg
      ids
      (read-json (third rest))
      (read-json (fourth rest))
      (read-json (fifth rest))
      (read-json (sixth rest)))))

(define (serialize-wire-msg msg key)
  (let* ((header  (json->string (jupyter-msg-header msg)))
         (parent  (json->string (jupyter-msg-parent msg)))
         (meta    (json->string (jupyter-msg-meta msg)))
         (content (json->string (jupyter-msg-content msg)))
         (sign    (if key
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

(define (start-shell-thread! socket key)
  (let ((fd (socket-fd socket)))
    (thread-start!
      (lambda ()
        (let loop ()
          (thread-wait-for-i/o! fd)
          (let* ((msg (parse-wire-msg (receive-message/multi socket) key))
                 (type (alist-ref 'msg_type (jupyter-msg-header msg))))
            (print "Received " type)
            (when (string=? "kernel_info_request" type)
              (print "reply!")
              (send-message/multi socket
                (serialize-wire-msg
                  (make-jupyter-msg* msg "kernel_info_reply"
                    `((protocol_version . "5.0")
                      (implementation . "moon")
                      (implementation_version . "0.1")
                      (banner . "")
                      (language_info .
                                     ((name . "scheme")
                                      (version . "4")
                                      (mimetype . "text/plain")
                                      (file_extension . "scm")))))
                  key)))
            (loop)))))))

(let* ((cfg (config->alist (car (command-line-arguments)))))
  (set! hmac-fn (hmac (alist-ref 'key cfg) (sha256-primitive)))

  (let-values (((hb shell) (punch cfg)))
    (start-hb-thread! hb)
    (start-shell-thread! shell (alist-ref 'key cfg)))

  ; pub cannot be read?
  #;(for-each
    (lambda (s x)
      (thread-start!
        (lambda ()
          (let loop ()
            (thread-wait-for-i/o! (socket-fd s))
            (print x #\: (receive-message/multi s))
            (loop)))))
    (cdddr socks) '(1 2 3))
)

(print "wait")
(thread-suspend! (current-thread))
(print "after-wait")
