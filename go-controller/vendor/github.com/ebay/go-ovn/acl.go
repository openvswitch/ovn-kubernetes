/**
 * Copyright (c) 2017 eBay Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **/

package goovn

import (
	"github.com/ebay/libovsdb"
)

// ACL ovnnb item
type ACL struct {
	UUID       string
	Action     string
	Direction  string
	Match      string
	Priority   int
	Log        bool
	Meter      []string
	Severity   string
	ExternalID map[interface{}]interface{}
}

func (odbi *ovndb) getACLUUIDByRow(entityType EntityType, entity string, row OVNRow) (string, error) {
	odbi.cachemutex.RLock()
	defer odbi.cachemutex.RUnlock()

	var tableName string

	switch entityType {
	case LOGICAL_SWITCH:
		tableName = TableLogicalSwitch
	case PORT_GROUP:
		tableName = TablePortGroup
	default:
		return "", ErrorOption
	}

	tableCache, ok := odbi.cache[tableName]
	if !ok {
		return "", ErrorSchema
	}

	for _, drows := range tableCache {
		if rlsw, ok := drows.Fields["name"].(string); ok && rlsw == entity {
			acls := drows.Fields["acls"]
			if acls != nil {
				switch acls.(type) {
				case libovsdb.OvsSet:
					if as, ok := acls.(libovsdb.OvsSet); ok {
						for _, a := range as.GoSet {
							if va, ok := a.(libovsdb.UUID); ok {
								cacheACL, ok := odbi.cache[TableACL][va.GoUUID]
								if !ok {
									return "", ErrorSchema
								}
								for field, value := range row {
									switch field {
									case "action":
										if cacheACL.Fields["action"].(string) != value {
											goto unmatched
										}
									case "direction":
										if cacheACL.Fields["direction"].(string) != value {
											goto unmatched
										}
									case "match":
										if cacheACL.Fields["match"].(string) != value {
											goto unmatched
										}
									case "priority":
										if cacheACL.Fields["priority"].(int) != value {
											goto unmatched
										}
									case "log":
										if cacheACL.Fields["log"].(bool) != value {
											goto unmatched
										}
									case "external_ids":
										if value != nil && !odbi.oMapContians(cacheACL.Fields["external_ids"].(libovsdb.OvsMap).GoMap, value.(*libovsdb.OvsMap).GoMap) {
											goto unmatched
										}
									}
								}
								return va.GoUUID, nil
							}
						unmatched:
						}
						return "", ErrorNotFound
					}
				case libovsdb.UUID:
					if va, ok := acls.(libovsdb.UUID); ok {
						cacheACL, ok := odbi.cache[TableACL][va.GoUUID]
						if !ok {
							return "", ErrorSchema
						}

						for field, value := range row {
							switch field {
							case "action":
								if cacheACL.Fields["action"].(string) != value {
									goto out
								}
							case "direction":
								if cacheACL.Fields["direction"].(string) != value {
									goto out
								}
							case "match":
								if cacheACL.Fields["match"].(string) != value {
									goto out
								}
							case "priority":
								if cacheACL.Fields["priority"].(int) != value {
									goto out
								}
							case "log":
								if cacheACL.Fields["log"].(bool) != value {
									goto out
								}
							case "external_ids":
								if value != nil && !odbi.oMapContians(cacheACL.Fields["external_ids"].(libovsdb.OvsMap).GoMap, value.(*libovsdb.OvsMap).GoMap) {
									goto out
								}
							}
						}
						return va.GoUUID, nil
					out:
					}
				}
			}
		}
	}
	return "", ErrorNotFound
}

func (odbi *ovndb) aclAddImp(entityType EntityType, entity, direct, match, action string, priority int, external_ids map[string]string, logflag bool, meter, severity string) (*OvnCommand, error) {
	var table string

	switch entityType {
	case LOGICAL_SWITCH:
		table = TableLogicalSwitch
	case PORT_GROUP:
		table = TablePortGroup
	default:
		return nil, ErrorOption
	}

	namedUUID, err := newRowUUID()
	if err != nil {
		return nil, err
	}
	row := make(OVNRow)
	row["direction"] = direct
	row["match"] = match
	row["priority"] = priority

	_, err = odbi.getACLUUIDByRow(entityType, entity, row)
	switch err {
	case ErrorNotFound:
		break
	case nil:
		return nil, ErrorExist
	default:
		return nil, err
	}

	if external_ids != nil {
		oMap, err := libovsdb.NewOvsMap(external_ids)
		if err != nil {
			return nil, err
		}
		row["external_ids"] = oMap
	}

	row["action"] = action
	row["log"] = logflag
	if logflag {
		ok := odbi.meterFind(meter)
		if ok {
			row["meter"] = meter
		}
		switch severity {
		case "alert", "debug", "info", "notice", "warning":
			row["severity"] = severity
		case "":
			row["severity"] = "info"
		default:
			return nil, ErrorOption
		}
	}
	insertOp := libovsdb.Operation{
		Op:       opInsert,
		Table:    TableACL,
		Row:      row,
		UUIDName: namedUUID,
	}

	mutateUUID := []libovsdb.UUID{stringToGoUUID(namedUUID)}
	mutateSet, err := libovsdb.NewOvsSet(mutateUUID)
	if err != nil {
		return nil, err
	}
	mutation := libovsdb.NewMutation("acls", opInsert, mutateSet)
	condition := libovsdb.NewCondition("name", "==", entity)

	// simple mutate operation
	mutateOp := libovsdb.Operation{
		Op:        opMutate,
		Table:     table,
		Mutations: []interface{}{mutation},
		Where:     []interface{}{condition},
	}
	operations := []libovsdb.Operation{insertOp, mutateOp}
	return &OvnCommand{operations, odbi, make([][]map[string]interface{}, len(operations))}, nil
}

func (odbi *ovndb) aclSetMatchEntityImp(entityType EntityType, entity, direct, oldMatch, newMatch string, priority int)  (*OvnCommand, error) {
	row := make(OVNRow)
	row["direction"] = direct
	row["match"] = oldMatch
	row["priority"] = priority

	aclUUID, err := odbi.getACLUUIDByRow(entityType, entity, row)
	if err != nil {
		return nil, err
	} else if len(aclUUID) == 0 {
		return nil, ErrorNotFound
	}

	// Check if an ACL with the newMatch already exists
	row["match"] = newMatch
	_, err = odbi.getACLUUIDByRow(entityType, entity, row)
	if err == nil {
		return nil, ErrorExist
	}

	// remove keys that don't need to be updated
	delete(row,"direction")
	delete(row,"priority")

	condition := libovsdb.NewCondition("_uuid", "==", stringToGoUUID(aclUUID))
	updateOp := libovsdb.Operation{
		Op:    opUpdate,
		Table: TableACL,
		Row:   row,
		Where: []interface{}{condition},
	}
	operations := []libovsdb.Operation{updateOp}
	return &OvnCommand{operations, odbi, make([][]map[string]interface{}, len(operations))}, nil
}

func (odbi *ovndb) aCLSetLoggingEntityimp(entityType EntityType, entity, direct, match string, priority int, newLogflag bool, newMeter, newSeverity string) (*OvnCommand, error) {
	row := make(OVNRow)
	row["direction"] = direct
	row["match"] = match
	row["priority"] = priority

	aclUUID, err := odbi.getACLUUIDByRow(entityType, entity, row)
	if err != nil {
		return nil, err
	} else if len(aclUUID) == 0 {
		return nil, ErrorNotFound
	}

	// reinitialize row and add the fields that need to be updated
	row = make(OVNRow)
	row["log"] = newLogflag
	if newLogflag {
		ok := odbi.meterFind(newMeter)
		if ok {
			row["meter"] = newMeter
		}
		switch newSeverity {
		case "alert", "debug", "info", "notice", "warning":
			row["severity"] = newSeverity
		case "":
			row["severity"] = "info"
		default:
			return nil, ErrorOption
		}
	}

	condition := libovsdb.NewCondition("_uuid", "==", stringToGoUUID(aclUUID))
	updateOp := libovsdb.Operation{
		Op:    opUpdate,
		Table: TableACL,
		Row:   row,
		Where: []interface{}{condition},
	}
	operations := []libovsdb.Operation{updateOp}
	return &OvnCommand{operations, odbi, make([][]map[string]interface{}, len(operations))}, nil
}

func (odbi *ovndb) aclDelImp(entityType EntityType, entity, direct, match string, priority int, external_ids map[string]string) (*OvnCommand, error) {
	var table string

	switch entityType {
	case LOGICAL_SWITCH:
		table = TableLogicalSwitch
	case PORT_GROUP:
		table = TablePortGroup
	default:
		return nil, ErrorOption
	}

	row := make(OVNRow)

	wherecondition := []interface{}{}
	if direct != "" {
		row["direction"] = direct
	}
	if match != "" {
		row["match"] = match
	}
	//in ovn priority is greater than/equal 0,
	//if input the priority < 0, lots of acls will be deleted if matches direct and match condition judgement.
	if priority >= 0 {
		row["priority"] = priority
	}

	if external_ids != nil {
		oMap, err := libovsdb.NewOvsMap(external_ids)
		if err != nil {
			return nil, err
		}
		row["external_ids"] = oMap
	}

	aclUUID, err := odbi.getACLUUIDByRow(entityType, entity, row)
	if err != nil {
		return nil, err
	}

	uuidcondition := libovsdb.NewCondition("_uuid", "==", stringToGoUUID(aclUUID))
	wherecondition = append(wherecondition, uuidcondition)
	deleteOp := libovsdb.Operation{
		Op:    opDelete,
		Table: TableACL,
		Where: wherecondition,
	}

	mutation := libovsdb.NewMutation("acls", opDelete, stringToGoUUID(aclUUID))
	condition := libovsdb.NewCondition("name", "==", entity)

	// Simple mutate operation
	mutateOp := libovsdb.Operation{
		Op:        opMutate,
		Table:     table,
		Mutations: []interface{}{mutation},
		Where:     []interface{}{condition},
	}
	operations := []libovsdb.Operation{mutateOp, deleteOp}
	return &OvnCommand{operations, odbi, make([][]map[string]interface{}, len(operations))}, nil
}

func (odbi *ovndb) rowToACL(uuid string) *ACL {
	cacheACL, ok := odbi.cache[TableACL][uuid]
	if !ok {
		return nil
	}

	var meter []string
	switch cacheACL.Fields["meter"].(type) {
	case string:
		meter = []string{cacheACL.Fields["meter"].(string)}
	case libovsdb.OvsSet:
		for _, a := range cacheACL.Fields["meter"].(libovsdb.OvsSet).GoSet {
			meter = append(meter, a.(string))
		}
	default:
	}

	severity := ""
	switch cacheACL.Fields["severity"].(type) {
	case string:
		severity = cacheACL.Fields["severity"].(string)
	case libovsdb.OvsSet:
		for _, a := range cacheACL.Fields["severity"].(libovsdb.OvsSet).GoSet {
			severity = a.(string)
		}
	default:
	}

	acl := &ACL{
		UUID:       uuid,
		Action:     cacheACL.Fields["action"].(string),
		Direction:  cacheACL.Fields["direction"].(string),
		Match:      cacheACL.Fields["match"].(string),
		Priority:   cacheACL.Fields["priority"].(int),
		Log:        cacheACL.Fields["log"].(bool),
		Meter:      meter,
		Severity:   severity,
		ExternalID: cacheACL.Fields["external_ids"].(libovsdb.OvsMap).GoMap,
	}

	return acl
}

// Get all acl by lswitch
func (odbi *ovndb) aclListImp(entityType EntityType, entity string) ([]*ACL, error) {
	odbi.cachemutex.RLock()
	defer odbi.cachemutex.RUnlock()

	var tableName string

	switch entityType {
	case LOGICAL_SWITCH:
		tableName = TableLogicalSwitch
	case PORT_GROUP:
		tableName = TablePortGroup
	default:
		return nil, ErrorOption
	}

	tableCache, ok := odbi.cache[tableName]
	if !ok {
		return nil, ErrorSchema
	}

	for _, drows := range tableCache {
		if rowName, ok := drows.Fields["name"].(string); ok && rowName == entity {
			acls := drows.Fields["acls"]
			if acls != nil {
				switch acls.(type) {
				case libovsdb.OvsSet:
					if as, ok := acls.(libovsdb.OvsSet); ok {
						listACL := make([]*ACL, 0, len(as.GoSet))
						for _, a := range as.GoSet {
							if va, ok := a.(libovsdb.UUID); ok {
								ta := odbi.rowToACL(va.GoUUID)
								listACL = append(listACL, ta)
							}
						}
						return listACL, nil
					}
				case libovsdb.UUID:
					if va, ok := acls.(libovsdb.UUID); ok {
						ta := odbi.rowToACL(va.GoUUID)
						return []*ACL{ta}, nil
					}
				}
			}
			return []*ACL{}, nil
		}
	}
	return nil, ErrorNotFound
}
