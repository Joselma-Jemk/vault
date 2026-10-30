; Installateur Windows de Vault (Inno Setup 6).
; Construit par le CI :
;   iscc /DAppVersion=0.1.0 /DGuiExe=dist\vault-gui.exe /DCliExe=dist\vault.exe packaging\vault.iss
; Sans droits administrateur par défaut (installation pour l'utilisateur courant), droits admin proposés au choix.
; Les données de l'utilisateur (%APPDATA%\Vault : coffre chiffré et journal) ne sont JAMAIS supprimées à la désinstallation.

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef GuiExe
  #define GuiExe "..\dist\vault-gui.exe"
#endif
#ifndef CliExe
  #define CliExe "..\dist\vault.exe"
#endif

[Setup]
AppId={{6DF4E4AC-D12F-4489-AD6E-FEADAF2A89CC}
AppName=Vault
AppVersion={#AppVersion}
AppVerName=Vault {#AppVersion}
AppPublisher=Joselma00
AppPublisherURL=https://github.com/Joselma-Jemk/vault
AppSupportURL=https://github.com/Joselma-Jemk/vault/issues
AppUpdatesURL=https://github.com/Joselma-Jemk/vault/releases
AppContact=contact@joselma.online
DefaultDirName={autopf}\Vault
DisableProgramGroupPage=yes
UninstallDisplayIcon={app}\vault-gui.exe
UninstallDisplayName=Vault {#AppVersion}
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ChangesEnvironment=yes
LicenseFile=..\LICENSE
SetupIconFile=..\src\vault\assets\vault.ico
OutputDir=..\dist
OutputBaseFilename=vault-{#AppVersion}-windows-setup
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64compatible
CloseApplications=yes
VersionInfoVersion={#AppVersion}

[Languages]
Name: "french"; MessagesFile: "compiler:Languages\French.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "addtopath"; Description: "Ajouter la commande « vault » au PATH (vault list, vault run… dans un terminal)"; GroupDescription: "Ligne de commande :"

[Files]
Source: "{#GuiExe}"; DestDir: "{app}"; DestName: "vault-gui.exe"; Flags: ignoreversion
; La commande est toujours installée ; la tâche « addtopath » décide seulement si son dossier entre dans le PATH.
Source: "{#CliExe}"; DestDir: "{app}\bin"; DestName: "vault.exe"; Flags: ignoreversion
Source: "..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\Vault"; Filename: "{app}\vault-gui.exe"
Name: "{autodesktop}\Vault"; Filename: "{app}\vault-gui.exe"; Tasks: desktopicon

[Registry]
; PATH : dossier « bin » (qui ne contient que vault.exe). Utilisateur seul ou système selon le mode d'installation.
Root: HKCU; Subkey: "Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{code:PathWith|{app}\bin}"; Tasks: addtopath; Check: (not IsAdminInstallMode) and NeedsAddPath(ExpandConstant('{app}\bin'))
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; ValueType: expandsz; ValueName: "Path"; ValueData: "{code:PathWith|{app}\bin}"; Tasks: addtopath; Check: IsAdminInstallMode and NeedsAddPath(ExpandConstant('{app}\bin'))
; Option « Lancer au démarrage de Windows » de l'application : la valeur est retirée à la désinstallation.
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: none; ValueName: "Vault"; Flags: dontcreatekey uninsdeletevalue

[Run]
Filename: "{app}\vault-gui.exe"; Description: "{cm:LaunchProgram,Vault}"; Flags: nowait postinstall skipifsilent

[Code]
const
  UserEnvKey = 'Environment';
  SystemEnvKey = 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment';

function EnvRoot: Integer;
begin
  if IsAdminInstallMode then
    Result := HKEY_LOCAL_MACHINE
  else
    Result := HKEY_CURRENT_USER;
end;

function EnvSubkey: String;
begin
  if IsAdminInstallMode then
    Result := SystemEnvKey
  else
    Result := UserEnvKey;
end;

{ Vrai si le dossier n'est pas déjà dans le PATH (comparaison sans tenir compte de la casse). }
function NeedsAddPath(Dir: String): Boolean;
var
  Current: String;
begin
  if not RegQueryStringValue(EnvRoot, EnvSubkey, 'Path', Current) then
  begin
    Result := True;
    Exit;
  end;
  Result := Pos(';' + Uppercase(Dir) + ';', ';' + Uppercase(Current) + ';') = 0;
end;

{ Nouvelle valeur du PATH : l'ancienne + le dossier (sans « ; » superflu si le PATH était vide). }
function PathWith(Dir: String): String;
var
  Current: String;
begin
  if not RegQueryStringValue(EnvRoot, EnvSubkey, 'Path', Current) then
    Current := '';
  if Current = '' then
    Result := Dir
  else if Copy(Current, Length(Current), 1) = ';' then
    Result := Current + Dir
  else
    Result := Current + ';' + Dir;
end;

{ À la désinstallation : retire seulement notre dossier du PATH, le reste est conservé. }
procedure RemoveFromPath(Dir: String);
var
  Current: String;
begin
  if not RegQueryStringValue(EnvRoot, EnvSubkey, 'Path', Current) then
    Exit;
  Current := ';' + Current + ';';
  StringChangeEx(Current, ';' + Dir + ';', ';', True);
  if (Length(Current) > 0) and (Current[1] = ';') then
    Delete(Current, 1, 1);
  if (Length(Current) > 0) and (Current[Length(Current)] = ';') then
    Delete(Current, Length(Current), 1);
  RegWriteExpandStringValue(EnvRoot, EnvSubkey, 'Path', Current);
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    RemoveFromPath(ExpandConstant('{app}\bin'));
end;
