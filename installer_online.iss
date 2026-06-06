; Inno Setup online/bootstrap installer для MortyScan v18
; Этот Setup.exe НЕ содержит внутри MortyScan.exe,
; а скачивает portable-бинарник из GitHub Releases и затем устанавливает его.

#define MyAppName "MortyScan"
#ifndef MyAppVersion
  #define MyAppVersion "18.0.0"
#endif
#ifndef MyAppPublisher
  #define MyAppPublisher "MortyScan Team"
#endif
#ifndef MyAppExeName
  #define MyAppExeName "MortyScan.exe"
#endif
#ifndef MyPortableAssetName
  #define MyPortableAssetName "MortyScan.exe"
#endif
#ifndef MyReleaseTag
  #define MyReleaseTag "v18.0.0"
#endif
#ifndef MyRepoOwner
  #define MyRepoOwner "FakeMorty"
#endif
#ifndef MyRepoName
  #define MyRepoName "mortyscan"
#endif

[Setup]
AppId={{B7A9C4E2-3F1A-4D5E-9B8C-2A6F5E3D4C7B}}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DisableProgramGroupPage=no
OutputDir=Output
OutputBaseFilename=Setup
SetupIconFile=icon.ico
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequiredOverridesAllowed=dialog
PrivilegesRequired=admin
ChangesEnvironment=yes
ArchitecturesInstallIn64BitMode=x64compatible
VersionInfoVersion={#MyAppVersion}
UninstallDisplayIcon={app}\icon.ico

[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"; InfoBeforeFile: "README.md"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "addtopath"; Description: "Добавить MortyScan в PATH (для использования в cmd/PowerShell)"; GroupDescription: "Дополнительно"; Flags: unchecked

[Files]
Source: "README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "icon.ico"; DestDir: "{app}"; Flags: ignoreversion
Source: "{tmp}\{#MyPortableAssetName}"; DestDir: "{app}"; DestName: "{#MyAppExeName}"; Flags: external ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\icon.ico"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\icon.ico"; Tasks: desktopicon

[Registry]
Root: HKCU; Subkey: "Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; Check: NeedsAddPath(ExpandConstant('{app}')); Tasks: addtopath

[Code]
var
  DownloadPage: TDownloadWizardPage;
  DownloadedPortable: Boolean;

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

function PortableDownloadUrl(): string;
begin
  Result := 'https://github.com/{#MyRepoOwner}/{#MyRepoName}/releases/download/{#MyReleaseTag}/{#MyPortableAssetName}';
end;

function OnDownloadProgress(const Url, FileName: String; const Progress, ProgressMax: Int64): Boolean;
begin
  Result := True;
end;

procedure InitializeWizard();
begin
  DownloadPage := CreateDownloadPage(
    'Загрузка MortyScan',
    'Setup сейчас скачает актуальный MortyScan.exe из GitHub Releases.',
    @OnDownloadProgress
  );
  DownloadedPortable := False;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;

  if (CurPageID = wpReady) and (not DownloadedPortable) then
  begin
    DownloadPage.Clear;
    DownloadPage.Add(PortableDownloadUrl(), '{#MyPortableAssetName}', '');
    DownloadPage.Show;
    try
      DownloadPage.Download;
      DownloadedPortable := True;
    except
      SuppressibleMsgBox(
        'Не удалось скачать {#MyPortableAssetName} из GitHub Releases.'#13#10#13#10 + GetExceptionMessage,
        mbCriticalError,
        MB_OK,
        IDOK
      );
      Result := False;
    finally
      DownloadPage.Hide;
    end;
  end;
end;

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Запустить MortyScan"; Flags: postinstall skipifsilent
