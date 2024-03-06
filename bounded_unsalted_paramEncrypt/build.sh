gcc -g \
 -o app \
-D MAXLOGLEVEL=6 \
-L /usr/local/lib \
-I /usr/local/include \
-I /usr/local/include/tss2 \
-I dep/ \
dep/sys-session-util.c \
dep/sys-entity-util.c \
dep/sys-util.c \
dep/sys-context-util.c \
main_bound_unsalted_ParamEncryp.c \
-ltss2-tctildr -ltss2-sys -lcrypto -ltss2-mu
