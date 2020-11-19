/*
 * Add UE Tool
 *
 * The tool adds a group of UEs to free5GC database, i.e. Mongo DB, with a range of consecutive SUPIs. The SUPI of the
 * first UE starts with the constant `baseUeSupi` and the rest of SUPIs increase numerically to a total number of the
 * constant `numOfUe`. The code is referred to the Web Console (free5gc/webconsole/backend/WebUI/api_webui.go).
 */

package main

import (
	"encoding/json"
	"fmt"

	"go.mongodb.org/mongo-driver/bson"

	"free5gc/lib/MongoDBLibrary"
	"free5gc/lib/openapi/models"
	"free5gc/webconsole/backend/WebUI"
)

const (
	authSubsDataColl = "subscriptionData.authenticationData.authenticationSubscription"
	amDataColl       = "subscriptionData.provisionedData.amData"
	smDataColl       = "subscriptionData.provisionedData.smData"
	smfSelDataColl   = "subscriptionData.provisionedData.smfSelectionSubscriptionData"
	amPolicyDataColl = "policyData.ues.amData"
	smPolicyDataColl = "policyData.ues.smData"
)

const (
	mongoUri   = "mongodb://127.0.0.1:27017"
	plmnId     = "20893"
	baseUeSupi = 3
	numOfUe    = 1000
	authMethod = "5G_AKA"
	k          = "8baf473f2f8fd09487cccbd7097c6862"
	opc        = "8e27b6af0e692e750f32667a3b14605d"
	baseSeqNum = 25235952177127
)

func main() {
	MongoDBLibrary.SetMongoDB("free5gc", mongoUri)

	subsData := WebUI.SubsData{
		PlmnID: plmnId,
		AuthenticationSubscription: models.AuthenticationSubscription{
			AuthenticationManagementField: "8000",
			AuthenticationMethod:          authMethod,
			Milenage:                      &models.Milenage{
				// Op: &models.Op{
				// 	EncryptionAlgorithm: 0,
				// 	EncryptionKey:       0,
				// 	OpValue:             "",
				// },
			},
			Opc: &models.Opc{
				EncryptionAlgorithm: 0,
				EncryptionKey:       0,
				OpcValue:            opc,
			},
			PermanentKey: &models.PermanentKey{
				EncryptionAlgorithm: 0,
				EncryptionKey:       0,
				PermanentKeyValue:   k,
			},
		},
		AccessAndMobilitySubscriptionData: models.AccessAndMobilitySubscriptionData{
			Gpsis: []string{
				"msisdn-0900000000",
			},
			Nssai: &models.Nssai{
				DefaultSingleNssais: []models.Snssai{
					{
						Sd:  "010203",
						Sst: 1,
					},
					{
						Sd:  "112233",
						Sst: 1,
					},
				},
				SingleNssais: []models.Snssai{
					{
						Sd:  "010203",
						Sst: 1,
					},
					{
						Sd:  "112233",
						Sst: 1,
					},
				},
			},
			SubscribedUeAmbr: &models.AmbrRm{
				Downlink: "2 Gbps",
				Uplink:   "1 Gbps",
			},
		},
		SessionManagementSubscriptionData: models.SessionManagementSubscriptionData{
			SingleNssai: &models.Snssai{
				Sst: 1,
				Sd:  "010203",
			},
			DnnConfigurations: map[string]models.DnnConfiguration{
				"internet": models.DnnConfiguration{
					PduSessionTypes: &models.PduSessionTypes{
						DefaultSessionType:  models.PduSessionType_IPV4,
						AllowedSessionTypes: []models.PduSessionType{models.PduSessionType_IPV4},
					},
					SscModes: &models.SscModes{
						DefaultSscMode:  models.SscMode__1,
						AllowedSscModes: []models.SscMode{models.SscMode__1},
					},
					SessionAmbr: &models.Ambr{
						Downlink: "2 Gbps",
						Uplink:   "1 Gbps",
					},
					Var5gQosProfile: &models.SubscribedDefaultQos{
						Var5qi: 9,
						Arp: &models.Arp{
							PriorityLevel: 8,
						},
						PriorityLevel: 8,
					},
				},
			},
		},
		SmfSelectionSubscriptionData: models.SmfSelectionSubscriptionData{
			SubscribedSnssaiInfos: map[string]models.SnssaiInfo{
				"01010203": {
					DnnInfos: []models.DnnInfo{
						{
							Dnn: "internet",
						},
					},
				},
				"01112233": {
					DnnInfos: []models.DnnInfo{
						{
							Dnn: "internet",
						},
					},
				},
			},
		},
		AmPolicyData: models.AmPolicyData{
			SubscCats: []string{
				"free5gc",
			},
		},
		SmPolicyData: models.SmPolicyData{
			SmPolicySnssaiData: map[string]models.SmPolicySnssaiData{
				"01010203": {
					Snssai: &models.Snssai{
						Sd:  "010203",
						Sst: 1,
					},
					SmPolicyDnnData: map[string]models.SmPolicyDnnData{
						"internet": {
							Dnn: "internet",
						},
					},
				},
				"01112233": {
					Snssai: &models.Snssai{
						Sd:  "112233",
						Sst: 1,
					},
					SmPolicyDnnData: map[string]models.SmPolicyDnnData{
						"internet": {
							Dnn: "internet",
						},
					},
				},
			},
		},
	}

	for idx := 0; idx < numOfUe; idx++ {
		ueId := fmt.Sprintf("imsi-%s%010d", plmnId, baseUeSupi+idx)
		subsData.UeId = ueId
		subsData.AuthenticationSubscription.SequenceNumber = fmt.Sprintf("%x", baseSeqNum+idx)

		filterUeIdOnly := bson.M{"ueId": ueId}
		filter := bson.M{"ueId": ueId, "servingPlmnId": plmnId}

		authSubsBsonM := toBsonM(subsData.AuthenticationSubscription)
		authSubsBsonM["ueId"] = ueId
		amDataBsonM := toBsonM(subsData.AccessAndMobilitySubscriptionData)
		amDataBsonM["ueId"] = ueId
		amDataBsonM["servingPlmnId"] = plmnId
		smDataBsonM := toBsonM(subsData.SessionManagementSubscriptionData)
		smDataBsonM["ueId"] = ueId
		smDataBsonM["servingPlmnId"] = plmnId
		smfSelSubsBsonM := toBsonM(subsData.SmfSelectionSubscriptionData)
		smfSelSubsBsonM["ueId"] = ueId
		smfSelSubsBsonM["servingPlmnId"] = plmnId
		amPolicyDataBsonM := toBsonM(subsData.AmPolicyData)
		amPolicyDataBsonM["ueId"] = ueId
		smPolicyDataBsonM := toBsonM(subsData.SmPolicyData)
		smPolicyDataBsonM["ueId"] = ueId

		MongoDBLibrary.RestfulAPIPutOne(authSubsDataColl, filterUeIdOnly, authSubsBsonM)
		MongoDBLibrary.RestfulAPIPutOne(amDataColl, filter, amDataBsonM)
		MongoDBLibrary.RestfulAPIPutOne(smDataColl, filter, smDataBsonM)
		MongoDBLibrary.RestfulAPIPutOne(smfSelDataColl, filter, smfSelSubsBsonM)
		MongoDBLibrary.RestfulAPIPutOne(amPolicyDataColl, filterUeIdOnly, amPolicyDataBsonM)
		MongoDBLibrary.RestfulAPIPutOne(smPolicyDataColl, filterUeIdOnly, smPolicyDataBsonM)
	}
}

func toBsonM(data interface{}) (ret bson.M) {
	tmp, _ := json.Marshal(data)
	json.Unmarshal(tmp, &ret)
	return
}
