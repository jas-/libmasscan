/* Upstream output.c with its report functions renamed. hooks.c wraps them. */
#define output_report_status lm_orig_output_report_status
#define output_report_banner lm_orig_output_report_banner
#include "output.c"
