#include <CUnit/CUnit.h>
#include <CUnit/Automated.h>
#include "CUnit/Console.h"
#include "CUnit/Automated.h"
#include "CUnit/CUCurses.h"   /* only on systems having curses */


void suite_Utility(void);
void suite_CcnClient(void);
void suite_SeqNum(void);
void suite_NdnlpPkt(void);
void suite_MsgSlicer(void);
void suite_PartialMsg(void);
void suite_SentPkt(void);
void suite_Link(void);

int main(void) {
	CU_initialize_registry();

	suite_Utility();
	suite_CcnClient();
	suite_SeqNum();
	suite_NdnlpPkt();
	suite_MsgSlicer();
	suite_PartialMsg();
	suite_SentPkt();
	suite_Link();

	CU_automated_run_tests();
	CU_console_run_tests();
	CU_curses_run_tests();
	CU_list_tests_to_file();
	CU_cleanup_registry();
	return 0;
}

