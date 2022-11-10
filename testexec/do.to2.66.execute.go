package testexec

import (
	fdodocommon "github.com/WebauthnWorks/fdo-device-implementation/common"
	"github.com/WebauthnWorks/fdo-device-implementation/to2"
	fdoshared "github.com/WebauthnWorks/fdo-shared"
	"github.com/WebauthnWorks/fdo-shared/testcom"
	testdbs "github.com/WebauthnWorks/fdo-shared/testcom/dbs"
	reqtestsdeps "github.com/WebauthnWorks/fdo-shared/testcom/request"
)

func preExecuteTo2_66(reqte reqtestsdeps.RequestTestInst) (*to2.To2Requestor, error) {
	testCred, err := reqte.TestVouchers.GetVoucher(testcom.NULL_TEST)
	if err != nil {
		return nil, err
	}

	// Generating TO0 handler
	to2requestor := to2.NewTo2Requestor(fdodocommon.SRVEntry{
		SrvURL: reqte.URL,
	}, testCred.WawDeviceCredential, fdoshared.KEX_ECDH256, fdoshared.CIPHER_A128GCM) // TODO

	proveOVHdrPayload61, _, err := to2requestor.HelloDevice60(testcom.NULL_TEST)
	if err != nil {
		return nil, err
	}

	var ovEntries fdoshared.OVEntryArray
	for i := 0; i < int(proveOVHdrPayload61.NumOVEntries); i++ {
		nextEntry, _, err := to2requestor.GetOVNextEntry62(uint8(i), testcom.NULL_TEST)
		if err != nil {
			return nil, err

		}

		if nextEntry.OVEntryNum != uint8(i) {
			return nil, err
		}

		ovEntries = append(ovEntries, nextEntry.OVEntry)
	}

	err = ovEntries.VerifyEntries(proveOVHdrPayload61.OVHeader, proveOVHdrPayload61.HMac)
	if err != nil {
		return nil, err
	}

	lastOvEntry := ovEntries[len(ovEntries)-1]
	loePubKey, _ := lastOvEntry.GetOVEntryPubKey()

	err = to2requestor.ProveOVHdr61PubKey.Equals(loePubKey)
	if err != nil {
		return nil, err
	}

	_, _, err = to2requestor.ProveDevice64(testcom.NULL_TEST)
	if err != nil {
		return nil, err
	}

	return &to2requestor, nil

}

func executeTo2_66(reqte reqtestsdeps.RequestTestInst, reqtDB *testdbs.RequestTestDB) {
	for _, testId := range testcom.FIDO_TEST_LIST_DOT_66 {
		to2requestor, err := preExecuteTo2_66(reqte)
		if err != nil {
			reqtDB.ReportTest(reqte.Uuid, testId, testcom.FDOTestState{
				Passed: false,
				Error:  "Error running TO2 DeviceServiceInfoReady66 batch. Pre setup failed. " + err.Error(),
			})
			return
		}

		switch testId {
		case testcom.FIDO_DOT_66_POSITIVE:
			_, _, err := to2requestor.DeviceServiceInfoReady66(testId)
			if err != nil {
				reqtDB.ReportTest(reqte.Uuid, testId, testcom.FDOTestState{
					Passed: false,
					Error:  err.Error(),
				})
				return
			} else {
				reqtDB.ReportTest(reqte.Uuid, testId, testcom.FDOTestState{
					Passed: true,
				})
			}

		default:
			_, rvtTestState, err := to2requestor.DeviceServiceInfoReady66(testId)
			if rvtTestState == nil && err != nil {
				errTestState := testcom.FDOTestState{
					Passed: false,
					Error:  err.Error(),
				}

				rvtTestState = &errTestState
			}

			reqtDB.ReportTest(reqte.Uuid, testId, *rvtTestState)
		}
	}
}
