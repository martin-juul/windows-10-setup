# Google Drive File Stream Setup

$folder = "c:\temp\gdfs"
If(!(Test-Path $folder))
{
      New-Item -ItemType Directory -Force -Path $folder
}
$url= "https://dl.google.com/drive-file-stream/GoogleDriveFSSetup.exe"
$req = [System.Net.HttpWebRequest]::Create($url)
$req.Method = "HEAD"
$response = $req.GetResponse()
$fUri = $response.ResponseUri
$filename = [System.IO.Path]::GetFileName($fUri.LocalPath);
$response.Close()
$target = Join-Path $folder $filename
$download = New-Object System.Net.WebClient
$download.DownloadFile($url, $target)

echo "Google Drive File Stream downloaded"

echo "Installing..."

Start-Process -FilePath $target

echo "You can delete the directory C:\temp\gdfs after install"
