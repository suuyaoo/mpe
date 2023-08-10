package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"log"
	"os"
	"reflect"

	"github.com/jedib0t/go-pretty/v6/table"
	peparser "github.com/saferwall/pe"
)

func ReadInteger[V uint64 | uint32 | uint16](data []byte, offset int) V {
	var value V
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Uint16:
		value = V(binary.LittleEndian.Uint16(data[offset : offset+2]))
	case reflect.Uint32:
		value = V(binary.LittleEndian.Uint32(data[offset : offset+4]))
	case reflect.Uint64:
		value = V(binary.LittleEndian.Uint64(data[offset : offset+8]))
	}
	return value
}

func WriteInteger[V uint64 | uint32 | uint16](data []byte, offset int, value V) {
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Uint16:
		binary.LittleEndian.PutUint16(data[offset:offset+2], uint16(value))
	case reflect.Uint32:
		binary.LittleEndian.PutUint32(data[offset:offset+4], uint32(value))
	case reflect.Uint64:
		binary.LittleEndian.PutUint64(data[offset:offset+8], uint64(value))
	}
}

// 打印导出函数表格
func listExportFuncs(srcfilename string) {
	if srcfilename == "" {
		return
	}
	pe, err := peparser.New(srcfilename, &peparser.Options{})
	if err != nil {
		log.Fatalf("Error while reading file: %s, reason: %v", srcfilename, err)
	}
	err = pe.Parse()
	if err != nil {
		log.Fatalf("Error while parsing file: %s, reason: %v", srcfilename, err)
	}
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{
		"#",
		"Ordinal",
		"FunctionRVA",
		"NameOrdinal",
		"NameRVA",
		"Name",
	})
	for i, efunc := range pe.Export.Functions {
		t.AppendRow(table.Row{
			i,
			efunc.Ordinal,
			efunc.FunctionRVA,
			efunc.NameOrdinal,
			efunc.NameRVA,
			efunc.Name,
		})
	}
	t.Render()
}

func getChecksum(data []byte) uint32 {
	pe, err := peparser.NewBytes(data, &peparser.Options{})
	if err != nil {
		return 0
	}
	err = pe.Parse()
	if err != nil {
		return 0
	}
	return pe.Checksum()
}

func getOptionalHeader(pe *peparser.File) ([]byte, uint32) {
	ntHeaderOffset := pe.DOSHeader.AddressOfNewEXEHeader
	fileHeaderSize := uint32(binary.Size(pe.NtHeader.FileHeader))
	optHeaderOffset := ntHeaderOffset + (fileHeaderSize + 4)
	size := uint32(binary.Size(peparser.ImageOptionalHeader64{}))
	if pe.Is32 {
		size = uint32(binary.Size(peparser.ImageOptionalHeader32{}))
	}
	dataOri, _ := pe.ReadBytesAtOffset(optHeaderOffset, size)
	data := make([]byte, size)
	copy(data, dataOri)
	return data, optHeaderOffset
}

func getExportDirectory(pe *peparser.File) peparser.DataDirectory {
	if pe.Is32 {
		return pe.NtHeader.OptionalHeader.(peparser.ImageOptionalHeader32).DataDirectory[peparser.ImageDirectoryEntryExport]
	}
	return pe.NtHeader.OptionalHeader.(peparser.ImageOptionalHeader64).DataDirectory[peparser.ImageDirectoryEntryExport]
}

// 删除指定的导出函数
func delExportFunc(delFuncName string, srcfilename string, dstfilename string) {
	if delFuncName == "" {
		return
	}
	if srcfilename == "" {
		return
	}
	if dstfilename == "" {
		return
	}
	filebufOri, err := os.ReadFile(srcfilename)
	if err != nil {
		log.Fatalf("Error while opening file: %s, reason: %v", srcfilename, err)
	}
	pe, err := peparser.NewBytes(filebufOri, &peparser.Options{})
	if err != nil {
		log.Fatalf("Error while reading file: %s, reason: %v", srcfilename, err)
	}
	err = pe.Parse()
	if err != nil {
		log.Fatalf("Error while parsing file: %s, reason: %v", srcfilename, err)
	}

	filebuf := make([]byte, len(filebufOri))
	copy(filebuf, filebufOri)

	dataOptHeader, dataOptHeaderOffset := getOptionalHeader(pe)

	dirExport := getExportDirectory(pe)
	dataExportOri, err := pe.GetData(dirExport.VirtualAddress, dirExport.Size)
	if err != nil {
		log.Fatalf("Error while get export data from file: %s, reason: %v", srcfilename, err)
	}

	dataExport := make([]byte, dirExport.Size)
	copy(dataExport, dataExportOri)

	// 函数地址表
	funcAddrTableOff := pe.Export.Struct.AddressOfFunctions - dirExport.VirtualAddress
	funcAddrTableSize := 4 * pe.Export.Struct.NumberOfFunctions
	funcAddrTable := dataExport[funcAddrTableOff : funcAddrTableOff+funcAddrTableSize]
	// 函数名地址表
	nameAddrTableOff := pe.Export.Struct.AddressOfNames - dirExport.VirtualAddress
	nameAddrTableSize := 4 * pe.Export.Struct.NumberOfNames
	nameAddrTable := dataExport[nameAddrTableOff : nameAddrTableOff+nameAddrTableSize]
	// 函数名序号表
	nameOrdiTableOff := pe.Export.Struct.AddressOfNameOrdinals - dirExport.VirtualAddress
	nameOrdiTableSize := 2 * pe.Export.Struct.NumberOfNames
	nameOrdiTable := dataExport[nameOrdiTableOff : nameOrdiTableOff+nameOrdiTableSize]
	// dll名 + 函数名表
	nameTable := dataExport[pe.Export.Struct.Name-dirExport.VirtualAddress:]

	// 构造新的 dll名 + 函数名表
	nameArray := bytes.Split(nameTable, []byte("\x00"))
	nameTableNew := make([]byte, 0)
	nameOffsetMap := make(map[string]uint32, 0)
	nameOffset := uint32(0)
	for _, name := range nameArray {
		if bytes.Equal(name, []byte(delFuncName)) {
			continue
		}
		if bytes.Equal(name, []byte("")) {
			continue
		}
		nameTableNew = append(nameTableNew, name...)
		nameTableNew = append(nameTableNew, []byte("\x00")...)
		nameOffsetMap[string(name)] = nameOffset
		nameOffset += uint32(len(name) + 1)
	}
	paddingLen := len(nameTable) - len(nameTableNew)
	for i := 0; i < paddingLen; i++ {
		nameTableNew = append(nameTableNew, []byte("\x00")...)
	}

	delFunc := peparser.ExportFunction{}

	delFuncIndex := -1
	sortedFunctions := make(map[int]peparser.ExportFunction, 0)
	for _, efunc := range pe.Export.Functions {
		i := 0
		for ; i < int(pe.Export.Struct.NumberOfNames); i++ {
			if ReadInteger[uint32](nameAddrTable, i*4) == efunc.NameRVA {
				break
			}
		}
		sortedFunctions[i] = efunc
		if efunc.Name == delFuncName {
			delFuncIndex = i
			delFunc = efunc
		}
	}

	if delFuncIndex == -1 {
		// 没有找到匹配的导出函数
		return
	}

	// 更新函数对应的名字地址以及名字序号
	for i, efunc := range sortedFunctions {
		if efunc.Name == delFuncName {
			continue
		}
		nameRVA := nameOffsetMap[efunc.Name]
		nameRVA = pe.Export.Struct.Name + nameRVA
		if i > delFuncIndex {
			WriteInteger[uint32](nameAddrTable, i*4-4, nameRVA)
			WriteInteger[uint16](nameOrdiTable, i*2-2, uint16(efunc.NameOrdinal))
		} else {
			WriteInteger[uint32](nameAddrTable, i*4, nameRVA)
			WriteInteger[uint16](nameOrdiTable, i*2, uint16(efunc.NameOrdinal))
		}
	}

	WriteInteger[uint32](funcAddrTable, int(delFunc.Ordinal-pe.Export.Struct.Base)*4, 0)

	WriteInteger[uint32](dataExport, 6*4, pe.Export.Struct.NumberOfNames-1)
	copy(dataExport[funcAddrTableOff:funcAddrTableOff+funcAddrTableSize], funcAddrTable)
	copy(dataExport[nameAddrTableOff:nameAddrTableOff+nameAddrTableSize], nameAddrTable)
	copy(dataExport[nameOrdiTableOff:nameOrdiTableOff+nameOrdiTableSize], nameOrdiTable)
	copy(dataExport[pe.Export.Struct.Name-dirExport.VirtualAddress:], nameTableNew)

	// 写入新的文件
	dirExportOffset := pe.GetOffsetFromRva(dirExport.VirtualAddress)
	copy(filebuf[dirExportOffset:dirExportOffset+dirExport.Size], dataExport)

	// 更新校验码
	checksum := getChecksum(filebuf)
	WriteInteger[uint32](dataOptHeader, 64, checksum)
	copy(filebuf[dataOptHeaderOffset:int(dataOptHeaderOffset)+len(dataOptHeader)], dataOptHeader)

	os.WriteFile(dstfilename, filebuf, 0644)
}

// 修改指定的导出函数
func modExportFunc(srcFuncName string, dstFuncName string, srcfilename string, dstfilename string) {
	if srcFuncName == "" {
		return
	}
	if dstFuncName == "" {
		return
	}
	if srcfilename == "" {
		return
	}
	if dstfilename == "" {
		return
	}
	filebufOri, err := os.ReadFile(srcfilename)
	if err != nil {
		log.Fatalf("Error while opening file: %s, reason: %v", srcfilename, err)
	}
	pe, err := peparser.NewBytes(filebufOri, &peparser.Options{})
	if err != nil {
		log.Fatalf("Error while reading file: %s, reason: %v", srcfilename, err)
	}
	err = pe.Parse()
	if err != nil {
		log.Fatalf("Error while parsing file: %s, reason: %v", srcfilename, err)
	}

	filebuf := make([]byte, len(filebufOri))
	copy(filebuf, filebufOri)

	dataOptHeader, dataOptHeaderOffset := getOptionalHeader(pe)

	dirExport := getExportDirectory(pe)
	dataExportOri, err := pe.GetData(dirExport.VirtualAddress, dirExport.Size)
	if err != nil {
		log.Fatalf("Error while get export data from file: %s, reason: %v", srcfilename, err)
	}

	dataExport := make([]byte, dirExport.Size)
	copy(dataExport, dataExportOri)

	// 函数地址表
	funcAddrTableOff := pe.Export.Struct.AddressOfFunctions - dirExport.VirtualAddress
	funcAddrTableSize := 4 * pe.Export.Struct.NumberOfFunctions
	funcAddrTable := dataExport[funcAddrTableOff : funcAddrTableOff+funcAddrTableSize]
	// 函数名地址表
	nameAddrTableOff := pe.Export.Struct.AddressOfNames - dirExport.VirtualAddress
	nameAddrTableSize := 4 * pe.Export.Struct.NumberOfNames
	nameAddrTable := dataExport[nameAddrTableOff : nameAddrTableOff+nameAddrTableSize]
	// 函数名序号表
	nameOrdiTableOff := pe.Export.Struct.AddressOfNameOrdinals - dirExport.VirtualAddress
	nameOrdiTableSize := 2 * pe.Export.Struct.NumberOfNames
	nameOrdiTable := dataExport[nameOrdiTableOff : nameOrdiTableOff+nameOrdiTableSize]
	// dll名 + 函数名表
	nameTable := dataExport[pe.Export.Struct.Name-dirExport.VirtualAddress:]

	// 构造新的 dll名 + 函数名表
	nameArray := bytes.Split(nameTable, []byte("\x00"))
	nameTableNew := make([]byte, 0)
	nameOffsetMap := make(map[string]uint32, 0)
	nameOffset := uint32(0)
	for _, name := range nameArray {
		if bytes.Equal(name, []byte("")) {
			continue
		}
		if bytes.Equal(name, []byte(srcFuncName)) {
			nameTableNew = append(nameTableNew, []byte(dstFuncName)...)
			nameTableNew = append(nameTableNew, []byte("\x00")...)
			nameOffsetMap[string(name)] = nameOffset
			nameOffset += uint32(len(dstFuncName) + 1)
		} else {
			nameTableNew = append(nameTableNew, name...)
			nameTableNew = append(nameTableNew, []byte("\x00")...)
			nameOffsetMap[string(name)] = nameOffset
			nameOffset += uint32(len(name) + 1)
		}
	}
	paddingLen := len(nameTable) - len(nameTableNew)
	for i := 0; i < paddingLen; i++ {
		nameTableNew = append(nameTableNew, []byte("\x00")...)
	}

	srcFuncIndex := -1
	sortedFunctions := make(map[int]peparser.ExportFunction, 0)
	for _, efunc := range pe.Export.Functions {
		i := 0
		for ; i < int(pe.Export.Struct.NumberOfNames); i++ {
			if ReadInteger[uint32](nameAddrTable, i*4) == efunc.NameRVA {
				break
			}
		}
		sortedFunctions[i] = efunc
		if efunc.Name == srcFuncName {
			srcFuncIndex = i
		}
	}

	if srcFuncIndex == -1 {
		// 没有找到匹配的导出函数
		return
	}

	// 更新函数对应的名字地址以及名字序号
	for i, efunc := range sortedFunctions {
		nameRVA := nameOffsetMap[efunc.Name]
		nameRVA = pe.Export.Struct.Name + nameRVA
		WriteInteger[uint32](nameAddrTable, i*4, nameRVA)
		WriteInteger[uint16](nameOrdiTable, i*2, uint16(efunc.NameOrdinal))
	}

	copy(dataExport[funcAddrTableOff:funcAddrTableOff+funcAddrTableSize], funcAddrTable)
	copy(dataExport[nameAddrTableOff:nameAddrTableOff+nameAddrTableSize], nameAddrTable)
	copy(dataExport[nameOrdiTableOff:nameOrdiTableOff+nameOrdiTableSize], nameOrdiTable)
	copy(dataExport[pe.Export.Struct.Name-dirExport.VirtualAddress:], nameTableNew)

	// 写入新的文件
	dirExportOffset := pe.GetOffsetFromRva(dirExport.VirtualAddress)
	copy(filebuf[dirExportOffset:dirExportOffset+dirExport.Size], dataExport)

	// 更新校验码
	checksum := getChecksum(filebuf)
	WriteInteger[uint32](dataOptHeader, 64, checksum)
	copy(filebuf[dataOptHeaderOffset:int(dataOptHeaderOffset)+len(dataOptHeader)], dataOptHeader)

	os.WriteFile(dstfilename, filebuf, 0644)
}

// 修改指定的导出函数
func modExportName(dstExportName string, srcfilename string, dstfilename string) {
	if dstExportName == "" {
		return
	}
	if srcfilename == "" {
		return
	}
	if dstfilename == "" {
		return
	}
	filebufOri, err := os.ReadFile(srcfilename)
	if err != nil {
		log.Fatalf("Error while opening file: %s, reason: %v", srcfilename, err)
	}
	pe, err := peparser.NewBytes(filebufOri, &peparser.Options{})
	if err != nil {
		log.Fatalf("Error while reading file: %s, reason: %v", srcfilename, err)
	}
	err = pe.Parse()
	if err != nil {
		log.Fatalf("Error while parsing file: %s, reason: %v", srcfilename, err)
	}

	filebuf := make([]byte, len(filebufOri))
	copy(filebuf, filebufOri)

	dataOptHeader, dataOptHeaderOffset := getOptionalHeader(pe)

	dirExport := getExportDirectory(pe)
	dataExportOri, err := pe.GetData(dirExport.VirtualAddress, dirExport.Size)
	if err != nil {
		log.Fatalf("Error while get export data from file: %s, reason: %v", srcfilename, err)
	}

	dataExport := make([]byte, dirExport.Size)
	copy(dataExport, dataExportOri)

	// 函数地址表
	funcAddrTableOff := pe.Export.Struct.AddressOfFunctions - dirExport.VirtualAddress
	funcAddrTableSize := 4 * pe.Export.Struct.NumberOfFunctions
	funcAddrTable := dataExport[funcAddrTableOff : funcAddrTableOff+funcAddrTableSize]
	// 函数名地址表
	nameAddrTableOff := pe.Export.Struct.AddressOfNames - dirExport.VirtualAddress
	nameAddrTableSize := 4 * pe.Export.Struct.NumberOfNames
	nameAddrTable := dataExport[nameAddrTableOff : nameAddrTableOff+nameAddrTableSize]
	// 函数名序号表
	nameOrdiTableOff := pe.Export.Struct.AddressOfNameOrdinals - dirExport.VirtualAddress
	nameOrdiTableSize := 2 * pe.Export.Struct.NumberOfNames
	nameOrdiTable := dataExport[nameOrdiTableOff : nameOrdiTableOff+nameOrdiTableSize]
	// dll名 + 函数名表
	nameTable := dataExport[pe.Export.Struct.Name-dirExport.VirtualAddress:]

	// 构造新的 dll名 + 函数名表
	nameArray := bytes.Split(nameTable, []byte("\x00"))
	nameTableNew := make([]byte, 0)
	nameOffsetMap := make(map[string]uint32, 0)
	nameOffset := uint32(0)
	for i, name := range nameArray {
		if bytes.Equal(name, []byte("")) {
			continue
		}
		if i == 0 {
			nameTableNew = append(nameTableNew, []byte(dstExportName)...)
			nameTableNew = append(nameTableNew, []byte("\x00")...)
			nameOffsetMap[string(name)] = nameOffset
			nameOffset += uint32(len(dstExportName) + 1)
		} else {
			nameTableNew = append(nameTableNew, name...)
			nameTableNew = append(nameTableNew, []byte("\x00")...)
			nameOffsetMap[string(name)] = nameOffset
			nameOffset += uint32(len(name) + 1)
		}
	}
	paddingLen := len(nameTable) - len(nameTableNew)
	for i := 0; i < paddingLen; i++ {
		nameTableNew = append(nameTableNew, []byte("\x00")...)
	}

	sortedFunctions := make(map[int]peparser.ExportFunction, 0)
	for _, efunc := range pe.Export.Functions {
		i := 0
		for ; i < int(pe.Export.Struct.NumberOfNames); i++ {
			if ReadInteger[uint32](nameAddrTable, i*4) == efunc.NameRVA {
				break
			}
		}
		sortedFunctions[i] = efunc
	}

	// 更新函数对应的名字地址以及名字序号
	for i, efunc := range sortedFunctions {
		nameRVA := nameOffsetMap[efunc.Name]
		nameRVA = pe.Export.Struct.Name + nameRVA
		WriteInteger[uint32](nameAddrTable, i*4, nameRVA)
		WriteInteger[uint16](nameOrdiTable, i*2, uint16(efunc.NameOrdinal))
	}

	copy(dataExport[funcAddrTableOff:funcAddrTableOff+funcAddrTableSize], funcAddrTable)
	copy(dataExport[nameAddrTableOff:nameAddrTableOff+nameAddrTableSize], nameAddrTable)
	copy(dataExport[nameOrdiTableOff:nameOrdiTableOff+nameOrdiTableSize], nameOrdiTable)
	copy(dataExport[pe.Export.Struct.Name-dirExport.VirtualAddress:], nameTableNew)

	// 写入新的文件
	dirExportOffset := pe.GetOffsetFromRva(dirExport.VirtualAddress)
	copy(filebuf[dirExportOffset:dirExportOffset+dirExport.Size], dataExport)

	// 更新校验码
	checksum := getChecksum(filebuf)
	WriteInteger[uint32](dataOptHeader, 64, checksum)
	copy(filebuf[dataOptHeaderOffset:int(dataOptHeaderOffset)+len(dataOptHeader)], dataOptHeader)

	os.WriteFile(dstfilename, filebuf, 0644)
}

func main() {
	cmdPtr := flag.String("cmd", "", "cmd to execute list|mod|del|mdll")
	srcfilenamePtr := flag.String("src-file", "", "src dll file name")
	dstfilenamePtr := flag.String("dst-file", "", "dst dll file name")
	srcfuncnamePtr := flag.String("src-func", "", "src func name")
	dstfuncnamePtr := flag.String("dst-func", "", "dst func name")
	dstdllnamePtr := flag.String("dst-name", "", "dst dll name")

	flag.Parse()

	if *cmdPtr == "" {
		return
	}
	if *cmdPtr == "list" {
		listExportFuncs(*srcfilenamePtr)
	}
	if *cmdPtr == "mod" {
		modExportFunc(*srcfuncnamePtr, *dstfuncnamePtr, *srcfilenamePtr, *dstfilenamePtr)
	}
	if *cmdPtr == "del" {
		delExportFunc(*srcfuncnamePtr, *srcfilenamePtr, *dstfilenamePtr)
	}
	if *cmdPtr == "mdll" {
		modExportName(*dstdllnamePtr, *srcfilenamePtr, *dstfilenamePtr)
	}
}
