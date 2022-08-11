#примеры использования PSPKI
```
#Install-Module -Name PSPKI
```
1) отозвать сертификаты
```
import-module pspki
#нужно задать свой адрес сервера и шаблон
$adcsserver="adcs01.test.loc"
$template="1.3.6.1.4.1.311.21.8.13954309.9887930.9521039.15715224.4226860.116.724438.4097016"
Get-CA $adcsserver | Get-IssuedRequest -Property CertificateTemplate | Where-Object {$_.CertificateTemplate -eq $template} | revoke-certificate
```
2) удалить из AD:
```
import-module pspki
import-module activedirectory
#нужно задать свой адрес сервера и шаблон
$adcsserver="adcs01.test.loc"
$template="1.3.6.1.4.1.311.21.8.13954309.9887930.9521039.15715224.4226860.116.724438.4097016"
$logpath=$env:userprofile+"\documents\log.txt"
"" | out-file $logpath -encoding UTF8
#Если сертификаты не отозваны
$certs=Get-CA $adcsserver | Get-issuedRequest -Properties CertificateTemplate,RequesterName | Where-Object {$_.CertificateTemplate -eq $template}
#если уже отозваны используется get-revokedrequest
#$certs=Get-CA $adcsserver | Get-revokedRequest -Properties CertificateTemplate,RequesterName | Where-Object {$_.CertificateTemplate -eq $template}
if ($certs -ne $null){
	foreach ($cert in $certs){
		$username=$cert.'Request.RequesterName' -replace ".*\\",""
		$user=get-aduser $username -properties usercertificate,certificates
		#Можно ограничить некоторыми OU, что б не удалять сразу у всех пользователей
		#$user=get-aduser -SearchBase "OU=users-ou,DC=test,DC=loc" -Filter {samaccountname -eq $username} -properties usercertificate,certificates
		if ($user.certificates.count -gt 0){
			foreach($usercert in $user.Certificates){
				$certV2 = New-Object  System.Security.Cryptography.X509Certificates.X509Certificate2 $usercert
				if ($certV2.serialNumber -eq $cert.serialnumber){
					try{
						set-aduser $user.samaccountname -certificates @{remove=$usercert} -erroraction stop
						"certificate removed from AD user object - $username. Certificate SN - $($cert.serialNumber)`n" | out-file $logpath -encoding UTF8 -append
						write-host "certificate removed from user ojcet - $username. Certificate SN - $($cert.serialNumber)`n" 
					}
					catch {
						$removeerror="unable to remove certificate $($certv2.serialnumber) for user $username `n"
						$removeerror+=$_
						$removeerror+="`n"
						write-host $removeerror -foregroundcolor red
						$removeerror | out-file $logpath -encoding UTF8 -append
					}
				}
			}
		}
	}
}
```


3) Выгрузить список:
```
import-module pspki
$csvpath=$env:userprofile+"\documents\certs.csv"
#нужно задать свой адрес сервера
$adcsserver="adcs01.test.loc"
$rawcerts=Get-CA $adcsserver | Get-IssuedRequest -Properties rawcertificate,requestattributes
"requester;subject;from;to;issuer;ccm;rmd;template" | out-file $csvpath -encoding utf8
foreach ($rawcert in $rawcerts){
	##для автоматически выданных сертификтов
    if (($rawcert.'Request.RequesterName'.ToString()) -like "*$"){
		$Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
		$requester=$rawcert.'Request.RequesterName'
		$cert.Import([convert]::frombase64string($rawcert.rawcertificate))
		$subject=$cert.subject
		$from=$cert.NotBefore
		$to=$cert.NotAfter
		$issuer=$cert.issuer
		$ccm=$rawcert.'Request.RequestAttributes' | findstr "ccm"
		$rmd=$rawcert.'Request.RequestAttributes' | findstr "rmd"
		$template=$rawcert.certificatetemplate
		$requester+";"+$subject+";"+$from+";"+$to+";"+$issuer+";"+$ccm+";"+$rmd+";"+$template | out-file $csvpath -append -encoding utf8
	}
	##если необходима информация о сертификатах выданных например для IIS, где отображается имя запросившего, а не сервера, можно использовать имена шаблонов
	elseif ($rawcert.certificatetemplate -like "*WebServer*"){
		$Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
		$requester=$rawcert.'Request.RequesterName'
		$cert.Import([convert]::frombase64string($rawcert.rawcertificate))
		$subject=$cert.subject
		$from=$cert.NotBefore
		$to=$cert.NotAfter
		$issuer=$cert.issuer
		$ccm=$rawcert.'Request.RequestAttributes' | findstr "ccm"
		$rmd=$rawcert.'Request.RequestAttributes' | findstr "rmd"
		$template=$rawcert.certificatetemplate
		$requester+";"+$subject+";"+$from+";"+$to+";"+$issuer+";"+$ccm+";"+$rmd+";"+$template | out-file $csvpath -append -encoding utf8
	}
}
```