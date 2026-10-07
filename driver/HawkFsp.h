#include "HawkeyeTfe.h"

IO_WORKITEM_ROUTINE HawkFspDispatch;

VOID
HawkQueueFspWorkItem(
    __in PHAWK_IRP_CONTEXT IrpContext
    );

FLT_PREOP_CALLBACK_STATUS
HawkPreWriteCompleteMdl(
    __in PVOID Context
    );
