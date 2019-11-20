;;; Emacs support for hacking on NetworkManager

(c-add-style "NetworkManager"
             '(
               ; Start with the "bsd" style
               "bsd"

               ; ...but remove the rule saying labels must be indented at
               ; least one space
               (c-label-minimum-indentation . 0)

               ; 4-space tabs/indents
               (tab-width . 4)
               (c-basic-offset . 4)

               ; Use smart-tabs-mode (see below) to get tabs for indentation
               ; but spaces for alignment of continuation lines.
               (smart-tabs-mode . t)

               ; Multi-line "if" conditions are indented like this:
               ;     if (   foo
               ;         && bar)
               ; (You have to add the spaces on the first line yourself, but
               ; this will make emacs align the "&&" correctly.)
               (c-offsets-alist (arglist-cont-nonempty . (nm-lineup-arglist))
                                (arglist-close . (nm-lineup-arglist)))

               ; NM's comments use two spaces after a period and are
               ; (generally) wrapped at 80 characters
               (sentence-end-double-space . t)
               (fill-column . 80)
               ))

;; http://www.emacswiki.org/emacs/SmartTabs
(require 'smart-tabs-mode)

;; The smart-tabs-mode documentation tells you to use
;; smart-tabs-insinuate to set it up, but that will cause it to be
;; enabled for *all* C code. We only want to enable it for
;; NetworkManager, so we have to manually set it up first.
(smart-tabs-advice c-indent-line c-basic-offset)
(smart-tabs-advice c-indent-region c-basic-offset)


;; Implements the weird "if" alignment
(defun nm-lineup-arglist (langelem)
  (save-excursion
    (back-to-indentation)
    (c-go-up-list-backward)
    (vector (+ (current-column) 1))))


(dir-locals-set-class-variables 'nm '((c-mode . ((c-file-style . "NetworkManager")))))

;; Now add a line like the following for every directory where you want the
;; "NetworkManager" style to be the default

; (dir-locals-set-directory-class "/home/danw/gnome/NetworkManager/" 'nm)
; (dir-locals-set-directory-class "/home/danw/gnome/network-manager-applet/" 'nm)

(provide 'networkmanager-style)
