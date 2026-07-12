package trigger

import "encoding/binary"

func testWorkspace(id uint32) [8]byte {
	var workspace [8]byte
	binary.BigEndian.PutUint32(workspace[:4], id)
	return workspace
}
