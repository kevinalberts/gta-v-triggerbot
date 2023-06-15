#AutoIt3Wrapper_UseX64=Y
#RequireAdmin
#NoTrayIcon
#include <NtProcess.au3>
#include <Misc.au3>
#include <Console.au3>

Global $iEntityType = IniRead(@ScriptDir & "\triggerbot.ini", "Triggerbot", "EntityType", Default)
Global $hKey = IniRead(@ScriptDir & "\triggerbot.ini", "Triggerbot", "Key", Default)
; GetEntityType() ; entity type (0 = empty, 1 = enemies, 2 = people, 3 = dead bodies, 4 = online friends, 5 = everything)
Global $TriggerbotSearch, $dwTriggerAddr, $TriggerBotBase, $Offset1Search, $dwOffset1, $TriggerBotAddress, $iTriggerType

cout("")
DllCall("Kernel32.dll", "BOOL", "SetConsoleTitle", "str", "GTA:V AutoUpdate Triggerbot")


$dwHandle = OpenProcess(0x1F0FFF, 0, ProcessExists("GTA5.exe"))
$dwBaseAddress = _MemoryModuleGetBaseAddress(ProcessExists("GTA5.exe"), "GTA5.exe")
Update()
cout("Triggerbot Address: " & @CRLF & $TriggerBotAddress, 0x5)
cout(@CRLF & @CRLF & "Triggerbot is running now.", 0xA)
cout(@CRLF & @CRLF & "Selected entity: ")
cout(GetEntityType(), 0x4)


While 1
	If _IsPressed($hKey) Then
		$iTriggerType = NtReadVirtualMemory($dwHandle, $TriggerBotAddress, "dword")
		If $iEntityType = 5 Then
			If $iTriggerType > 0 Then
				MouseClick("primary")
			EndIf
		Else
			If $iTriggerType = $iEntityType Then ; entity type (0 = empty, 1 = enemies, 2 = people, 3 = dead bodies, 4 = online friends, 5 = everything)
				MouseClick("primary")
			EndIf
		EndIf
	EndIf
WEnd


Func Update()
	$TriggerbotSearch = FindPatternX64($dwHandle, "488B15........488B0D........4C8D85........E8........488B15........488B0D........4C8D85........E8........488B15........488B0D........4C8D85........E8", false, $dwBaseAddress)
	$dwTriggerAddr = "0x" & Hex(NtReadVirtualMemory($dwHandle, $TriggerbotSearch + 0x3, "dword"), 8)
	$TriggerBotBase = "0x" & Hex(Execute($TriggerbotSearch + $dwTriggerAddr + 0x7), 12)
	$Offset1Search = FindPatternX64($dwHandle, "448997........F7EA448BCA", false, $dwBaseAddress)
	$dwOffset1 = "0x" & Hex(NtReadVirtualMemory($dwHandle, $Offset1Search + 0x3, "dword"), 8)
	$TriggerBotAddress = "0x" & Hex(Execute($TriggerBotBase + $dwOffset1 + 0x1C), 12)
EndFunc   ;==>Update

Func GetEntityType()
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
	ElseIf $iEntityType = 5 Then
		Return "All"
	EndIf
EndFunc   ;==>GetEntityType
