#include <cassert>
#include "CrispTest.h"
#include <iostream>

CrispTest::CrispTest() : crispDriver_() {
}

void CrispTest::assert_cs1_msg_send() {
	std::cout << "Testing CRISP CS1 message sending..." << std::endl;
	crispDriver_.configure_state_with_suite(externalKeyFlag_, key_, keyId_, sourceId_, 256, seqNum_1_3_, cs1_);

	std::vector<uint8_t> msg;
	crispDriver_.send(payloadData_, msg);

	assert(msg == crisp_msg_1_);
	std::cout << "CRISP CS1 message sending test passed successfully!" << std::endl;
}

void CrispTest::assert_cs2_msg_send() {
	std::cout << "Testing CRISP CS2 message sending..." << std::endl;
	crispDriver_.configure_state_with_suite(externalKeyFlag_, key_, keyId_, sourceId_, 256, seqNum_2_4_, cs2_);

	std::vector<uint8_t> msg;
	crispDriver_.send(payloadData_, msg);

	assert(msg == crisp_msg_2_);
	std::cout << "CRISP CS2 message sending test passed successfully!" << std::endl;
}

void CrispTest::assert_cs3_msg_send() {
	std::cout << "Testing CRISP CS3 message sending..." << std::endl;
	crispDriver_.configure_state_with_suite(externalKeyFlag_, key_, keyId_, sourceId_, 256, seqNum_1_3_, cs3_);

	std::vector<uint8_t> msg;
	crispDriver_.send(payloadData_, msg);

	assert(msg == crisp_msg_3_);
	std::cout << "CRISP CS3 message sending test passed successfully!" << std::endl;
}

void CrispTest::assert_cs4_msg_send() {
	std::cout << "Testing CRISP CS4 message sending..." << std::endl;
	crispDriver_.configure_state_with_suite(externalKeyFlag_, key_, keyId_, sourceId_, 256, seqNum_2_4_, cs4_);

	std::vector<uint8_t> msg;
	crispDriver_.send(payloadData_, msg);

	assert(msg == crisp_msg_4_);
	std::cout << "CRISP CS4 message sending test passed successfully!" << std::endl;
}

void CrispTest::assert_cs1_msg_receive() {
	std::cout << "Testing CRISP CS1 message receiving..." << std::endl;
	std::vector<uint8_t> received;
	crispDriver_.receive(key_, sourceId_, 256, crisp_msg_1_, received);

	assert(received == payloadData_);
	std::cout << "CRISP CS1 message receiving test passed successfully!" << std::endl;
}

void CrispTest::assert_cs2_msg_receive() {
	std::cout << "Testing CRISP CS2 message receiving..." << std::endl;
	std::vector<uint8_t> received;
	crispDriver_.receive(key_, sourceId_, 256, crisp_msg_2_, received);

	assert(received == payloadData_);
	std::cout << "CRISP CS2 message receiving test passed successfully!" << std::endl;
}

void CrispTest::assert_cs3_msg_receive() {
	std::cout << "Testing CRISP CS3 message receiving..." << std::endl;
	std::vector<uint8_t> received;
	crispDriver_.receive(key_, sourceId_, 256, crisp_msg_3_, received);

	assert(received == payloadData_);
	std::cout << "CRISP CS3 message receiving test passed successfully!" << std::endl;
}

void CrispTest::assert_cs4_msg_receive() {
	std::cout << "Testing CRISP CS4 message receiving..." << std::endl;
	std::vector<uint8_t> received;
	crispDriver_.receive(key_, sourceId_, 256, crisp_msg_4_, received);

	assert(received == payloadData_);
	std::cout << "CRISP CS4 message receiving test passed successfully!" << std::endl;
}

void CrispTest::assert_all_functions() {
	std::cout << "\nRunning all CRISP tests..." << std::endl;
	assert_cs1_msg_send();
	assert_cs2_msg_send();
	assert_cs3_msg_send();
	assert_cs4_msg_send();

	assert_cs1_msg_receive();
	assert_cs2_msg_receive();
	assert_cs3_msg_receive();
	assert_cs4_msg_receive();
	std::cout << "All CRISP tests completed successfully!" << std::endl;
}