Global Const $PAGE_EXECUTE = 0x10
Global Const $PAGE_EXECUTE_READ = 0x20
Global Const $PAGE_EXECUTE_READWRITE = 0x40
Global Const $PAGE_EXECUTE_WRITECOPY = 0x80

Global Const $PAGE_NOACCESS = 0x1
Global Const $PAGE_READONLY = 0x2
Global Const $PAGE_READWRITE = 0x4
Global Const $PAGE_WRITECOPY = 0x8

Global Const $MEM_COMMIT = 0x1000
Global Const $MEM_RESERVE = 0x2000
Global Const $MEM_RESET = 0x80000
Global Const $MEM_DECOMMIT = 0x4000
Global Const $MEM_RELEASE = 0x8000

Global Const $PROCESS_ALL_ACCESS = 0x1F0FFF

Func OpenProcess($dwAccess, $bInheritHandle, $dwProcessId)
	$ret = DllCall('kernel32.dll', 'dword', 'OpenProcess', 'dword', $dwAccess, 'bool', $bInheritHandle, 'dword', $dwProcessId)
	Return $ret[0]
EndFunc   ;==>OpenProcess

Func CloseHandle($hObject)
	$ret = DllCall('kernel32.dll', 'bool', 'CloseHandle', 'handle', $hObject)
	Return $ret[0]
EndFunc   ;==>CloseHandle

Func NtReadVirtualMemory($hProcess, $lpBaseAddress, $Type = 'dword')
	$dsBuffer = DllStructCreate($Type);
	DllCall('ntdll.dll', 'bool', 'NtReadVirtualMemory', 'handle', $hProcess, 'ptr', $lpBaseAddress, 'ptr', DllStructGetPtr($dsBuffer), 'int', DllStructGetSize($dsBuffer), 'int', 0)
	Return DllStructGetData($dsBuffer, 1)
EndFunc   ;==>NtReadVirtualMemory

Func NtWriteVirtualMemory($hProcess, $lpBaseAddress, $Value, $Type = 'dword')
	$dsBuffer = DllStructCreate($Type)
	DllStructSetData($dsBuffer, 1, $Value)
	DllCall('ntdll.dll', 'bool', 'NtWriteVirtualMemory', 'handle', $hProcess, 'ptr', $lpBaseAddress, 'ptr', DllStructGetPtr($dsBuffer), 'int', DllStructGetSize($dsBuffer), 'int', 0)
EndFunc   ;==>NtWriteVirtualMemory

Func NtAllocateVirtualMemory($hProcess, $lpAddress, $iSize, $dwAllocationType, $dwProtection)
	$ret = DllCall('ntdll.dll', 'int', 'NtAllocateVirtualMemory', 'handle', $hProcess, 'ptr', $lpAddress, 'dword', 0, 'int', $iSize, 'dword', $dwAllocationType, 'dword', $dwProtection)
	Return $ret[0]
EndFunc   ;==>NtAllocateVirtualMemory

Func NtFreeVirtualMemory($hProcess, $lpAddress, $iSize, $dwFreeType)
	$ret = DllCall('ntdll.dll', 'bool', 'NtFreeVirtualMemory', 'handle', $hProcess, 'ptr', $lpAddress, 'int', $iSize, 'dword', $dwFreeType)
	Return $ret[0]
EndFunc   ;==>NtFreeVirtualMemory

Func NtProtectVirtualMemory($hProcess, $lpAddress, $iSize, $dwNewProtection)
	$dsBuffer = DllStructCreate('dword')
	DllCall('ntdll.dll', 'bool', 'NtProtectVirtualMemory', 'handle', $hProcess, 'ptr', $lpAddress, 'int', $iSize, 'dword', $dwNewProtection, 'dword', DllStructGetPtr($dsBuffer))
	Return DllStructGetData($dsBuffer, 1)
EndFunc   ;==>NtProtectVirtualMemory

Func NtLockVirtualMemory($hProcess, $lpAddress, $iSize, $LockOption)
	$ret = DllCall('ntdll.dll', 'bool', 'NtLockVirtualMemory', 'handle', $hProcess, 'ptr', $lpAddress, 'int', $iSize, 'dword', $LockOption)
	Return $ret[0]
EndFunc   ;==>NtLockVirtualMemory

Func GetProcAddress($szFunctionname, $szDLL)
	$aRet = DllCall('kernel32.dll', 'handle', 'LoadLibrary', 'str', $szDLL)
	If $aRet[0] == 0 Then
		SetError(1)
		Return
	EndIf

	$pAdd = DllCall('kernel32.dll', 'ptr', 'GetProcAddress', 'handle', $aRet[0], 'str', $szFunctionname)
	If $pAdd[0] == 0 Then
		SetError(2)
		Return
	EndIf

	DllCall('kernel32.dll', 'bool', 'FreeLibrary', 'handle', $aRet[0])

	Return hex(number( $pAdd[0] ))
EndFunc   ;==>GetProcAddress

;credits to luzifer (not made by me, just edited to let it work with readprocessmemory)
Func FindPatternX32($ah_Handle, $pattern, $after = False, $iv_addrStart = 0x00000000, $iv_addrEnd = 0x7FFFFFFFFFF, $step = 51200)
	$pattern = StringRegExpReplace($pattern, "[^0123456789ABCDEFabcdef.]", "")
	If StringLen($pattern) = 0 Then
		SetError(2)
		Return -2
	EndIf
	For $addr = $iv_addrStart To $iv_addrEnd Step $step - (StringLen($pattern) / 2)
		StringRegExp(NtReadVirtualMemory($ah_Handle, $addr, "byte[" & $step & "]"), $pattern, 1, 2)
		If Not @error Then
			If $after Then
				Return StringFormat("0x%.8X", $addr + ((@extended - 2) / 2))
			Else
				Return StringFormat("0x%.8X", $addr + ((@extended - StringLen($pattern) - 2) / 2))
			EndIf
		EndIf
	Next
	Return -3
EndFunc   ;==>FindPattern

Func FindPatternX64($ah_Handle, $pattern, $after = False, $iv_addrStart = 0x00000000, $iv_addrEnd = 0x7FFFFFFFFFFF, $step = 51200)
   $pattern = StringRegExpReplace($pattern, "[^0123456789ABCDEFabcdef.]", "")
   For $addr = $iv_addrStart To $iv_addrEnd Step $step - (StringLen($pattern) / 2)
       $read = NtReadVirtualMemory($ah_Handle, $addr, "byte[" & $step & "]")
      StringRegExp($read, $pattern, 1, 2)
      If Not @error Then
         If $after Then
            Return StringFormat("0x%.8X", $addr + ((@extended - 2) / 2))
         Else
            Dim $ext = @extended
            $strl = ($ext - StringLen($pattern) - 4)
            $address = Execute($addr + ($strl / 2))
            Return "0x" & Hex($address,12)
         EndIf
      EndIf
   Next
   Return -3
EndFunc   ;==>FindPattern

Func Detour($hProcess, $lpAddress, $szCode, $iLength = 5)
	If StringLen($szCode) == 0 Then
		SetError(1)
		Return
	EndIf
	Local $ret[2] = [$lpAddress, ""]

	$oCode = StringSplit($szCode, "/")

	$Alloc = NtAllocateVirtualMemory($hProcess, 0, $oCode[0] + 12, $MEM_COMMIT, $PAGE_EXECUTE_READWRITE)
	If $Alloc == 0 Then
		SetError(2)
		Return
	EndIf

	For $i = 1 To $oCode[0] Step 1
		NtWriteVirtualMemory($hProcess, $Alloc + $i - 1, $oCode[$i])
	Next

	$tAddr = $Alloc+$oCode[0]

	NtWriteVirtualMemory($hProcess, $Alloc + $oCode[0], 0xE9)
	NtWriteVirtualMemory($hProcess, $Alloc + $oCode[0] + 1, ($lpAddress-$tAddr))

	$flOldProtect = NtProtectVirtualMemory($hProcess, $lpAddress, $iLength, $PAGE_EXECUTE_READWRITE)

	For $i = 0 To $iLength - 1 Step 1
		$ret[1] &= '0x' & Hex(NtReadVirtualMemory($hProcess, $lpAddress + $i, 'byte'), 2) & "/"
	Next

	NtWriteVirtualMemory($hProcess, $lpAddress, 0xE9)
	NtWriteVirtualMemory($hProcess, $lpAddress + 1, ($Alloc - $lpAddress) - $iLength, 'ptr')
	NtProtectVirtualMemory($hProcess, $lpAddress, $iLength, $flOldProtect)

	For $i = 0 To $iLength - 6 Step 1
		NtWriteVirtualMemory($hProcess, $lpAddress + 5 + $i, 0x90, 'byte')
	Next

	Return $ret

EndFunc   ;==>Detour

Func Retour($hProcess, $arDetour)
	If Not IsArray($arDetour) Then
		SetError(1)
		Return
	EndIf

	Local $oCode = StringSplit($arDetour[1], "/")
	Local $flOldProtect = NtProtectVirtualMemory($hProcess, $arDetour[0], $oCode[0], $PAGE_EXECUTE_READWRITE)

	For $i = 1 To $oCode[0] Step 1
		NtWriteVirtualMemory($hProcess, ($arDetour[0] + $i) - 1, $oCode[$i])
	Next

	NtProtectVirtualMemory($hProcess, $arDetour[0], $oCode[0], $flOldProtect)
	NtFreeVirtualMemory($hProcess, $arDetour[0], $oCode[0] + 12, $MEM_RELEASE)

	Return 1
EndFunc   ;==>Retour

Func MemSet($hProcess, $Address, $Value, $iSize)
	$flOldProtect = NtProtectVirtualMemory($hProcess, $Address, $iSize, $PAGE_EXECUTE_READWRITE)
	For $i = 0 To $iSize Step 1
		NtWriteVirtualMemory($hProcess, $Address + $i, $Value, 'byte')
	Next
	NtProtectVirtualMemory($hProcess, $Address, $iSize, $flOldProtect)
	Return
EndFunc   ;==>MemSet

Func MemCpy($hProcess, $Dst, $Src, $iSize)
	If $iSize == 0 Then
		SetError(1)
		Return
	EndIf

	For $i = 0 To $iSize
		$tByte = NtReadVirtualMemory($hProcess, $Src + $i, 'byte')
		NtWriteVirtualMemory($hProcess, $Dst + $i, $tByte, 'byte')
	Next

	Return
EndFunc   ;==>MemCpy

Func MemCmp($hProcess, $Reg1, $Reg2, $iSize)
	If $iSize == 0 Then
		SetError(1)
		Return
	EndIf

	Return StringCompare(NtReadVirtualMemory($hProcess, $Reg1, 'byte[' & $iSize & ']'), NtReadVirtualMemory($hProcess, $Reg2, 'byte[' & $iSize & ']'))
 EndFunc   ;==>MemCmp

 Func  _MemoryModuleGetBaseAddress($iPID , $sModule)
    If  Not  ProcessExists ($iPID) Then  Return  SetError (1 , 0 , 0)

    If  Not  IsString ($sModule) Then  Return  SetError (2 , 0 , 0)

    Local    $PSAPI=DllOpen ("psapi.dll")

    ;Get Process Handle
    Local    $hProcess
    Local    $PERMISSION=BitOR (0x0002, 0x0400, 0x0008, 0x0010, 0x0020) ; CREATE_THREAD, QUERY_INFORMATION, VM_OPERATION, VM_READ, VM_WRITE

    If  $iPID>0 Then
        Local  $hProcess=DllCall ("kernel32.dll" , "ptr" , "OpenProcess" , "dword" , $PERMISSION , "int" , 0 , "dword" , $iPID)
        If  $hProcess [ 0 ] Then
            $hProcess=$hProcess [ 0 ]
        EndIf
    EndIf

    ;EnumProcessModules
    Local    $Modules=DllStructCreate ("ptr[1024]")
    Local    $aCall=DllCall ($PSAPI , "int" , "EnumProcessModules" , "ptr" , $hProcess , "ptr" , DllStructGetPtr ($Modules), "dword" , DllStructGetSize ($Modules), "dword*" , 0)
    If  $aCall [ 4 ]>0 Then
        Local    $iModnum=$aCall [ 4 ] / 4
        Local    $aTemp
        For  $i=1 To  $iModnum
            $aTemp= DllCall ($PSAPI , "dword" , "GetModuleBaseNameW" , "ptr" , $hProcess , "ptr" , Ptr(DllStructGetData ($Modules , 1 , $i)) , "wstr" , "" , "dword" , 260)
            If  $aTemp [ 3 ]=$sModule Then
                DllClose ($PSAPI)
                Return  Ptr(DllStructGetData ($Modules , 1 , $i))
            EndIf
        Next
    EndIf

    DllClose ($PSAPI)
    Return  SetError (-1 , 0 , 0)

EndFunc