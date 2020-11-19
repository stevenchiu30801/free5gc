/*
 * Registration Tool
 *
 * The tool registers a single UE and establishes a session. After a session is established, the program blocks and
 * waits for the termination signal (Ctrl-c). One may use libgtpnl (https://github.com/osmocom/libgtpnl) to perform
 * data traffic test. Press Ctrl-c to resume the following deregistration procedure. The code is referred to the
 * Registration Test (free5gc/src/test/regitration_test.go).
 * TODO: The AmfUeNgapID, UE IP address and TEID shall be retrieved from NAS messages. Currently one may not execute
 * the tool consecutively.
 */

package main

import (
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"free5gc/lib/CommonConsumerTestData/UDM/TestGenAuthData"
	"free5gc/lib/MongoDBLibrary"
	"free5gc/lib/nas"
	"free5gc/lib/nas/nasMessage"
	"free5gc/lib/nas/nasTestpacket"
	"free5gc/lib/nas/nasType"
	"free5gc/lib/nas/security"
	"free5gc/lib/ngap"
	"free5gc/lib/ngap/ngapType"
	"free5gc/lib/openapi/models"
	"free5gc/src/test"
)

const (
	ranIpAddr = "192.168.2.3"
	amfIpAddr = "192.168.2.2"
	mongoAddr = "192.168.2.2"
)

func checkErr(err error) {
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
}

func main() {
	var n int
	var sendMsg []byte
	var recvMsg = make([]byte, 2048)

	// set Mongo DB
	MongoDBLibrary.SetMongoDB("free5gc", "mongodb://"+mongoAddr+":27017")

	// RAN connect to AMF
	conn, err := test.ConntectToAmf(amfIpAddr, ranIpAddr, 38412, 9487)
	checkErr(err)

	// RAN connect to UPF
	// upfConn, err := test.ConnectToUpf(ranIpAddr, "10.200.200.102", 2152, 2152)
	// checkErr(err)

	// send NGSetupRequest Msg
	sendMsg, err = test.GetNGSetupRequest([]byte("\x00\x01\x02"), 24, "free5gc")
	checkErr(err)
	_, err = conn.Write(sendMsg)
	checkErr(err)

	// receive NGSetupResponse Msg
	n, err = conn.Read(recvMsg)
	checkErr(err)
	ngapPdu, err := ngap.Decoder(recvMsg[:n])
	checkErr(err)
	if !(ngapPdu.Present == ngapType.NGAPPDUPresentSuccessfulOutcome && ngapPdu.SuccessfulOutcome.ProcedureCode.Value == ngapType.ProcedureCodeNGSetup) {
		fmt.Println("No NGSetupResponse received.")
		os.Exit(1)
	}

	// New UE
	// ue := test.NewRanUeContext("imsi-2089300007487", 1, security.AlgCiphering128NEA2, security.AlgIntegrity128NIA2)
	ue := test.NewRanUeContext("imsi-2089300007487", 1, security.AlgCiphering128NEA0, security.AlgIntegrity128NIA2)
	ue.AmfUeNgapId = 1
	ue.AuthenticationSubs = test.GetAuthSubscription(TestGenAuthData.MilenageTestSet19.K,
		TestGenAuthData.MilenageTestSet19.OPC,
		TestGenAuthData.MilenageTestSet19.OP)
	// insert UE data to MongoDB

	servingPlmnId := "20893"
	test.InsertAuthSubscriptionToMongoDB(ue.Supi, ue.AuthenticationSubs)
	// getData := test.GetAuthSubscriptionFromMongoDB(ue.Supi)
	// assert.NotNil(t, getData)
	{
		amData := test.GetAccessAndMobilitySubscriptionData()
		test.InsertAccessAndMobilitySubscriptionDataToMongoDB(ue.Supi, amData, servingPlmnId)
		// getData := test.GetAccessAndMobilitySubscriptionDataFromMongoDB(ue.Supi, servingPlmnId)
		// assert.NotNil(t, getData)
	}
	{
		smfSelData := test.GetSmfSelectionSubscriptionData()
		test.InsertSmfSelectionSubscriptionDataToMongoDB(ue.Supi, smfSelData, servingPlmnId)
		// getData := test.GetSmfSelectionSubscriptionDataFromMongoDB(ue.Supi, servingPlmnId)
		// assert.NotNil(t, getData)
	}
	{
		smSelData := test.GetSessionManagementSubscriptionData()
		test.InsertSessionManagementSubscriptionDataToMongoDB(ue.Supi, servingPlmnId, smSelData)
		// getData := test.GetSessionManagementDataFromMongoDB(ue.Supi, servingPlmnId)
		// assert.NotNil(t, getData)
	}
	{
		amPolicyData := test.GetAmPolicyData()
		test.InsertAmPolicyDataToMongoDB(ue.Supi, amPolicyData)
		// getData := test.GetAmPolicyDataFromMongoDB(ue.Supi)
		// assert.NotNil(t, getData)
	}
	{
		smPolicyData := test.GetSmPolicyData()
		test.InsertSmPolicyDataToMongoDB(ue.Supi, smPolicyData)
		// getData := test.GetSmPolicyDataFromMongoDB(ue.Supi)
		// assert.NotNil(t, getData)
	}

	// send InitialUeMessage(Registration Request)(imsi-2089300007487)
	mobileIdentity5GS := nasType.MobileIdentity5GS{
		Len:    12, // suci
		Buffer: []uint8{0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0x00, 0x00, 0x00, 0x00, 0x47, 0x78},
	}

	ueSecurityCapability := ue.GetUESecurityCapability()
	registrationRequest := nasTestpacket.GetRegistrationRequest(
		nasMessage.RegistrationType5GSInitialRegistration, mobileIdentity5GS, nil, ueSecurityCapability, nil, nil, nil)
	sendMsg, err = test.GetInitialUEMessage(ue.RanUeNgapId, registrationRequest, "")
	checkErr(err)
	_, err = conn.Write(sendMsg)
	checkErr(err)

	// receive NAS Authentication Request Msg
	n, err = conn.Read(recvMsg)
	checkErr(err)
	ngapPdu, err = ngap.Decoder(recvMsg[:n])
	checkErr(err)
	if !(ngapPdu.Present == ngapType.NGAPPDUPresentInitiatingMessage) {
		fmt.Println("No NGAP Initiating Message received.")
		os.Exit(1)
	}

	// Calculate for RES*
	nasPdu := test.GetNasPdu(ue, ngapPdu.InitiatingMessage.Value.DownlinkNASTransport)
	if nasPdu == nil {
		fmt.Println("Cannot get NAS-PDU in Initiating Message")
		os.Exit(1)
	}
	if !(nasPdu.GmmHeader.GetMessageType() == nas.MsgTypeAuthenticationRequest) {
		fmt.Println("No Authentication Request received.")
		os.Exit(1)
	}
	rand := nasPdu.AuthenticationRequest.GetRANDValue()
	resStat := ue.DeriveRESstarAndSetKey(ue.AuthenticationSubs, rand[:], "5G:mnc093.mcc208.3gppnetwork.org")

	// send NAS Authentication Response
	pdu := nasTestpacket.GetAuthenticationResponse(resStat, "")
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	checkErr(err)
	_, err = conn.Write(sendMsg)
	checkErr(err)

	// receive NAS Security Mode Command Msg
	n, err = conn.Read(recvMsg)
	checkErr(err)
	ngapPdu, err = ngap.Decoder(recvMsg[:n])
	checkErr(err)
	if ngapPdu == nil {
		fmt.Println("Cannot get NGAP-PDU in NAS Security Mode Command Message")
		os.Exit(1)
	}
	nasPdu = test.GetNasPdu(ue, ngapPdu.InitiatingMessage.Value.DownlinkNASTransport)
	if nasPdu == nil {
		fmt.Println("Cannot get NGAP-PDU in Downlink NAS Transport Message")
		os.Exit(1)
	}
	if !(nasPdu.GmmHeader.GetMessageType() == nas.MsgTypeSecurityModeCommand) {
		fmt.Println("No Security Mode Command received. Message: " + strconv.Itoa(int(nasPdu.GmmHeader.GetMessageType())))
		os.Exit(1)
	}

	// send NAS Security Mode Complete Msg
	registrationRequestWith5GMM := nasTestpacket.GetRegistrationRequest(nasMessage.RegistrationType5GSInitialRegistration,
		mobileIdentity5GS, nil, ueSecurityCapability, ue.Get5GMMCapability(), nil, nil)
	pdu = nasTestpacket.GetSecurityModeComplete(registrationRequestWith5GMM)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext, true, true)
	checkErr(err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	checkErr(err)
	_, err = conn.Write(sendMsg)
	checkErr(err)

	// receive ngap Initial Context Setup Request Msg
	n, err = conn.Read(recvMsg)
	checkErr(err)
	ngapPdu, err = ngap.Decoder(recvMsg[:n])
	checkErr(err)
	if !(ngapPdu.Present == ngapType.NGAPPDUPresentInitiatingMessage &&
		ngapPdu.InitiatingMessage.ProcedureCode.Value == ngapType.ProcedureCodeInitialContextSetup) {
		fmt.Println("No InitialContextSetup received.")
		os.Exit(1)
	}

	// send ngap Initial Context Setup Response Msg
	sendMsg, err = test.GetInitialContextSetupResponse(ue.AmfUeNgapId, ue.RanUeNgapId)
	checkErr(err)
	_, err = conn.Write(sendMsg)
	checkErr(err)

	// send NAS Registration Complete Msg
	pdu = nasTestpacket.GetRegistrationComplete(nil)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	checkErr(err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	checkErr(err)
	_, err = conn.Write(sendMsg)
	checkErr(err)

	time.Sleep(100 * time.Millisecond)
	// send GetPduSessionEstablishmentRequest Msg

	sNssai := models.Snssai{
		Sst: 1,
		Sd:  "010203",
	}
	pdu = nasTestpacket.GetUlNasTransport_PduSessionEstablishmentRequest(10, nasMessage.ULNASTransportRequestTypeInitialRequest, "internet", &sNssai)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	checkErr(err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	checkErr(err)
	_, err = conn.Write(sendMsg)
	checkErr(err)

	// receive 12. NGAP-PDU Session Resource Setup Request(DL nas transport((NAS msg-PDU session setup Accept)))
	n, err = conn.Read(recvMsg)
	checkErr(err)
	ngapPdu, err = ngap.Decoder(recvMsg[:n])
	checkErr(err)
	if !(ngapPdu.Present == ngapType.NGAPPDUPresentInitiatingMessage &&
		ngapPdu.InitiatingMessage.ProcedureCode.Value == ngapType.ProcedureCodePDUSessionResourceSetup) {
		fmt.Println("No PDUSessionResourceSetup received.")
		os.Exit(1)
	}

	// send 14. NGAP-PDU Session Resource Setup Response
	sendMsg, err = test.GetPDUSessionResourceSetupResponse(ue.AmfUeNgapId, ue.RanUeNgapId, ranIpAddr)
	checkErr(err)
	_, err = conn.Write(sendMsg)
	checkErr(err)

	// block and wait for termination signal
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c

	// send NAS Deregistration Request (UE Originating)
	mobileIdentity5GS = nasType.MobileIdentity5GS{
		Len:    11, // 5g-guti
		Buffer: []uint8{0x02, 0x02, 0xf8, 0x39, 0xca, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x01},
	}
	pdu = nasTestpacket.GetDeregistrationRequest(nasMessage.AccessType3GPP, 0, 0x04, mobileIdentity5GS)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	checkErr(err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	checkErr(err)
	_, err = conn.Write(sendMsg)
	checkErr(err)

	time.Sleep(500 * time.Millisecond)

	// receive Deregistration Accept
	n, err = conn.Read(recvMsg)
	checkErr(err)
	ngapPdu, err = ngap.Decoder(recvMsg[:n])
	checkErr(err)
	if !(ngapPdu.Present == ngapType.NGAPPDUPresentInitiatingMessage &&
		ngapPdu.InitiatingMessage.ProcedureCode.Value == ngapType.ProcedureCodeDownlinkNASTransport) {
		fmt.Println("No DownlinkNASTransport received.")
		os.Exit(1)
	}
	nasPdu = test.GetNasPdu(ue, ngapPdu.InitiatingMessage.Value.DownlinkNASTransport)
	if nasPdu == nil {
		fmt.Println("Cannot get NAS-PDU in Deregistration Accept")
		os.Exit(1)
	}
	if nasPdu.GmmMessage == nil {
		fmt.Println("Cannot get GMM Message in Deregistration Accept")
		os.Exit(1)
	}
	if !(nasPdu.GmmHeader.GetMessageType() == nas.MsgTypeDeregistrationAcceptUEOriginatingDeregistration) {
		fmt.Println("Received wrong GMM message")
		os.Exit(1)
	}

	// receive ngap UE Context Release Command
	n, err = conn.Read(recvMsg)
	checkErr(err)
	ngapPdu, err = ngap.Decoder(recvMsg[:n])
	checkErr(err)
	if !(ngapPdu.Present == ngapType.NGAPPDUPresentInitiatingMessage &&
		ngapPdu.InitiatingMessage.ProcedureCode.Value == ngapType.ProcedureCodeUEContextRelease) {
		fmt.Println("No UEContextReleaseCommand received.")
		os.Exit(1)
	}

	// send ngap UE Context Release Complete
	sendMsg, err = test.GetUEContextReleaseComplete(ue.AmfUeNgapId, ue.RanUeNgapId, nil)
	checkErr(err)
	_, err = conn.Write(sendMsg)
	checkErr(err)

	time.Sleep(100 * time.Millisecond)

	// delete test data
	test.DelAuthSubscriptionToMongoDB(ue.Supi)
	test.DelAccessAndMobilitySubscriptionDataFromMongoDB(ue.Supi, servingPlmnId)
	test.DelSmfSelectionSubscriptionDataFromMongoDB(ue.Supi, servingPlmnId)

	// close Connection
	conn.Close()
}
