#AutoIt3Wrapper_UseX64=Y
#RequireAdmin
#NoTrayIcon
#include <NtProcess.au3>
#include <Misc.au3>
#include <Console.au3>

Global $hDLL = DllOpen("user32.dll")
Global $dwTriggerbotFinal, $hProcess, $dwModuleBase, $iTriggerType
Global $iEntityType = 1 ; GetEnitityType()
Global $dwTriggerSearch, $dwTriggerLocation, $dwTriggerAddr, $dwTriggerPtr
Global $dwTriggerOffsetSearch, $dwTriggerOffsetLocation, $dwTriggerOffsetAddr, $dwTriggerbotFinal

cout("")
DllCall("Kernel32.dll", "BOOL", "SetConsoleTitle", "str", "GTA:V AutoUpdate Triggerbot")


$hProcess = OpenProcess(0x1F0FFF, 0, ProcessExists("GTA5.exe"))
$dwModuleBase = _MemoryModuleGetBaseAddress(ProcessExists("GTA5.exe"), "GTA5.exe")
Update()
cout("Triggerbot Address: " & @CRLF & "GTA5.exe + " & $dwTriggerbotFinal, 0x5)
cout(@CRLF & @CRLF & "Triggerbot is running now.", 0xA)
cout(@CRLF & @CRLF & "Selected entity: ")
cout(GetEnitityType(), 0x4)


While 1
	If _IsPressed("58", $hDLL) Then ;hotkey: G
		$iTriggerType = NtReadVirtualMemory($hProcess, $dwModuleBase + $dwTriggerbotFinal, "dword")
		If $iTriggerType = $iEntityType Then ; entity type (0 = empty, 1 = enemies, 2 = people, 3 = dead bodies, 4 = online friends)
			MouseClick("primary")
		EndIf
	EndIf
	Sleep(10)
WEnd


Func Update()
	$dwTriggerSearch = FindPattern($hProcess, "8B0D........E9........48895C24084889742410574883EC2033DB", False, $dwModuleBase)
	$dwTriggerLocation = "0x" & Hex(Execute($dwTriggerSearch - $dwModuleBase), 8)
	$dwTriggerAddr = "0x" & Hex(NtReadVirtualMemory($hProcess, $dwTriggerSearch + 0x2, "dword"), 8)
	$dwTriggerPtr = "0x" & Hex(Execute($dwTriggerLocation + $dwTriggerAddr + 0x6), 8)

	$dwTriggerOffsetSearch = FindPattern($hProcess, "418B85........C1E8..4184C775088ACA41", False, $dwModuleBase)
	$dwTriggerOffsetLocation = "0x" & Hex(Execute($dwTriggerOffsetSearch - $dwModuleBase), 8)
	$dwTriggerOffsetAddr = "0x" & Hex(NtReadVirtualMemory($hProcess, $dwTriggerOffsetSearch + 0x3, "dword"), 8)
	$dwTriggerbotFinal = "0x" & Hex(Execute($dwTriggerPtr - (($dwTriggerOffsetAddr * 0x7) + 0x1000)), 8) ; most retarded calculation in my entire life ngl
EndFunc   ;==>Update

Func GetEnitityType()
	If $iEntityType = 0 Then
		Return "Empty"
	ElseIf $iEntityType = 1 Then
		Return "Enemies"
	ElseIf $iEntityType = 2 Then
		Return "People"
	ElseIf $iEntityType = 3 Then
		Return "Dead bodies"
	ElseIf $iEntityType = 4 Then
		Return "Online Friends"
	EndIf
EndFunc   ;==>GetEnitityType

Func _MemoryModuleGetBaseAddress($iPID, $sModule)
	If Not ProcessExists($iPID) Then Return SetError(1, 0, 0)

	If Not IsString($sModule) Then Return SetError(2, 0, 0)

	Local $PSAPI = DllOpen("psapi.dll")

	;Get Process Handle
	Local $hProcess
	Local $PERMISSION = BitOR(0x0002, 0x0400, 0x0008, 0x0010, 0x0020)   ; CREATE_THREAD, QUERY_INFORMATION, VM_OPERATION, VM_READ, VM_WRITE

	If $iPID > 0 Then
		Local $hProcess = DllCall("kernel32.dll", "ptr", "OpenProcess", "dword", $PERMISSION, "int", 0, "dword", $iPID)
		If $hProcess[0] Then
			$hProcess = $hProcess[0]
		EndIf
	EndIf

	;EnumProcessModules
	Local $Modules = DllStructCreate("ptr[1024]")
	Local $aCall = DllCall($PSAPI, "int", "EnumProcessModules", "ptr", $hProcess, "ptr", DllStructGetPtr($Modules), "dword", DllStructGetSize($Modules), "dword*", 0)
	If $aCall[4] > 0 Then
		Local $iModnum = $aCall[4] / 4
		Local $aTemp
		For $i = 1 To $iModnum
			$aTemp = DllCall($PSAPI, "dword", "GetModuleBaseNameW", "ptr", $hProcess, "ptr", Ptr(DllStructGetData($Modules, 1, $i)), "wstr", "", "dword", 260)
			If $aTemp[3] = $sModule Then
				DllClose($PSAPI)
				Return Ptr(DllStructGetData($Modules, 1, $i))
			EndIf
		Next
	EndIf

	DllClose($PSAPI)
	Return SetError(-1, 0, 0)

EndFunc   ;==>_MemoryModuleGetBaseAddress
