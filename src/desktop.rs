//! Small desktop integrations. User-controlled values are arguments/environment,
//! never interpolated into shell or PowerShell source.
use anyhow::{bail, Result};
#[cfg(windows)]
use std::os::windows::process::CommandExt;
use std::{path::PathBuf, process::Command};

pub fn notify(title: &str, body: &str) {
    #[cfg(target_os = "linux")]
    let result = Command::new("notify-send")
        .args(["--app-name=BLEClip", "--", title, body])
        .spawn();
    #[cfg(windows)]
    let result = Command::new("powershell.exe").creation_flags(0x08000000)
        .args(["-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command",
            "Add-Type -AssemblyName System.Windows.Forms; Add-Type -AssemblyName System.Drawing; $n = New-Object System.Windows.Forms.NotifyIcon; $n.Icon = [System.Drawing.SystemIcons]::Information; $n.Visible = $true; $n.ShowBalloonTip(10000, $env:BLECLIP_TITLE, $env:BLECLIP_BODY, [System.Windows.Forms.ToolTipIcon]::Info); Start-Sleep -Seconds 11; $n.Dispose()"])
        .env("BLECLIP_TITLE", title).env("BLECLIP_BODY", body).spawn();
    // Reap helpers without blocking clipboard/BLE processing.
    match result {
        Ok(mut child) => {
            std::thread::spawn(move || {
                let _ = child.wait();
            });
        }
        Err(err) => eprintln!("{title}: {body} (desktop notification unavailable: {err})"),
    }
}

pub fn choose_files() -> Result<Vec<PathBuf>> {
    #[cfg(target_os = "linux")]
    let output = match Command::new("kdialog")
        .args([
            "--getopenfilename",
            ".",
            "*",
            "--multiple",
            "--separate-output",
            "--title",
            "Send files with BLEClip",
        ])
        .output()
    {
        Ok(output) => output,
        Err(_) => Command::new("zenity")
            .args([
                "--file-selection",
                "--multiple",
                "--separator=\n",
                "--title=Send files with BLEClip",
            ])
            .output()?,
    };
    #[cfg(windows)]
    let output = Command::new("powershell.exe").creation_flags(0x08000000).args(["-NoProfile", "-STA", "-Command",
        "Add-Type -AssemblyName System.Windows.Forms; [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new(); $d = New-Object System.Windows.Forms.OpenFileDialog; $d.Multiselect = $true; $d.Title = 'Send files with BLEClip'; if ($d.ShowDialog() -eq 'OK') { $d.FileNames }; $d.Dispose()"])
        .output()?;
    if !output.status.success() {
        if output.status.code() == Some(1) {
            return Ok(Vec::new());
        }
        bail!(
            "file picker failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8(output.stdout)?
        .lines()
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .collect())
}

pub fn prompt_text(title: &str, prompt: &str, value: &str) -> Result<Option<String>> {
    #[cfg(target_os = "linux")]
    let output = match Command::new("kdialog")
        .args(["--title", title, "--inputbox", prompt, value])
        .output()
    {
        Ok(output) => output,
        Err(_) => Command::new("zenity")
            .args([
                "--entry",
                "--title",
                title,
                "--text",
                prompt,
                "--entry-text",
                value,
            ])
            .output()?,
    };
    #[cfg(windows)]
    let output = Command::new("powershell.exe").creation_flags(0x08000000)
        .args(["-NoProfile", "-STA", "-Command", r#"
Add-Type -AssemblyName System.Windows.Forms
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new()
$f = New-Object System.Windows.Forms.Form
$f.Text = $env:BLECLIP_TITLE; $f.Width = 460; $f.Height = 190; $f.StartPosition = 'CenterScreen'
$l = New-Object System.Windows.Forms.Label; $l.Text = $env:BLECLIP_PROMPT; $l.SetBounds(12,12,420,42)
$t = New-Object System.Windows.Forms.TextBox; $t.Text = $env:BLECLIP_VALUE; $t.SetBounds(12,58,420,24)
$ok = New-Object System.Windows.Forms.Button; $ok.Text = 'OK'; $ok.DialogResult = 'OK'; $ok.SetBounds(250,100,85,28)
$cancel = New-Object System.Windows.Forms.Button; $cancel.Text = 'Cancel'; $cancel.DialogResult = 'Cancel'; $cancel.SetBounds(345,100,85,28)
$f.Controls.AddRange(@($l,$t,$ok,$cancel)); $f.AcceptButton = $ok; $f.CancelButton = $cancel
if ($f.ShowDialog() -eq 'OK') { [Console]::Write($t.Text) } else { $f.Dispose(); exit 1 }; $f.Dispose()
"#]).env("BLECLIP_TITLE",title).env("BLECLIP_PROMPT",prompt).env("BLECLIP_VALUE",value).output()?;
    if output.status.code() == Some(1) {
        return Ok(None);
    }
    if !output.status.success() {
        bail!(
            "settings dialog failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(Some(String::from_utf8(output.stdout)?.trim().to_owned()))
}

pub fn open_path(path: &std::path::Path) -> Result<()> {
    #[cfg(target_os = "linux")]
    let mut child = Command::new("xdg-open").arg(path).spawn()?;
    #[cfg(windows)]
    let mut child = Command::new("powershell.exe")
        .creation_flags(0x08000000)
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Start-Process -FilePath $env:BLECLIP_PATH",
        ])
        .env("BLECLIP_PATH", path)
        .spawn()?;
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}
