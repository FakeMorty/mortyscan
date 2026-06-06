; Inno Setup script для MortyScan v18.1
; Собирает MortyScan-Setup.exe, который ставит программу в Program Files,
; добавляет ярлык в меню Пуск и (опционально) в PATH.

#define MyAppName "MortyScan"
#define MyAppVersion "18.1.0"
#define MyAppPublisher "MortyScan Team"
#define MyAppExeName "MortyScan.exe"

[Setup]
AppId={{B7A9C4E2-3F1A-4D5E-9B8C-2A6F5E3D4C7B}}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DisableProgramGroupPage=no
OutputDir=Output
OutputBaseFilename=MortyScan-Setup
SetupIconFile=icon.ico
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequiredOverridesAllowed=dialog
PrivilegesRequired=admin

[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\\Russian.isl"; InfoBeforeFile: "README.md"

[Files]
Source: "dist\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "mortyscan\data\wordlist.txt"; DestDir: "{app}\mortyscan\data"; Flags: ignoreversion
Source: "icon.ico"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\icon.ico"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\icon.ico"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "addtopath"; Description: "Добавить MortyScan в PATH (для использования в cmd/PowerShell)"; GroupDescription: "Дополнительно"; Flags: unchecked

[Registry]
; Добавляем в PATH пользователя (если выбрана задача addtopath)
Root: HKCU; Subkey: "Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; Check: NeedsAddPath(ExpandConstant('{app}')); Tasks: addtopath

[Code]
function NeedsAddPath(Param: string): boolean;
var
  OrigPath: string;
begin
  if not RegQueryStringValue(HKCU, 'Environment', 'Path', OrigPath) then
  begin
    Result := true;
    exit;
  end;
  Result := Pos(Param + ';', OrigPath) = 0;
end;

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Запустить MortyScan"; Flags: postinstall skipifsilent
