Clear-Host
### SOURCES
$main_config_file = "C:\GitHub\StackOverflow\SEARCHLIGHT\searchlight_for_windows\config\main_config.conf"
$conf_values = Get-Content $main_config_file | Out-String | ConvertFrom-StringData
### VARIABLES
$root_path = $conf_values.root_path
$conf_path = $conf_values.conf_path
$data_path = $conf_values.data_path
$tmp_path = $conf_values.tmp_path
$users_data_file = $conf_values.users_data_file
$tmp_csv = $conf_values.users_all_data
$us_excl_list = $conf_values.us_excl_list
$timestamp_zero = $conf_values.timestamp_zero
$date_zero = $conf_values.date_zero
$date_format = $conf_values.date_format
$nc = $conf_values.nc
$val_true = $conf_values.val_true
$val_false = $conf_values.val_false
$date = Get-Date
### json database
$json_users_all_data_path = $root_path + $data_path + $users_data_file
$data_from_json = Get-Content $json_users_all_data_path -Raw | ConvertFrom-Json
$users = $data_from_json.entries.attributes
### csv config files
$us_excl_file = $root_path + $conf_path + $us_excl_list
$us_excl_data = Import-Csv $us_excl_file -Delimiter ";"
$users_excluded_list = $us_excl_data.sAMAccountName

### csv temporary file
$tmp_csv_data_path = $root_path + $tmp_path + $tmp_csv
$tmp_csv = New-Item -ItemType file -Force $tmp_csv_data_path
### functions
function is_account_excluded ($suspect) {
    $account = $true
    foreach ($user_excluded in $users_excluded_list) {
        if ($user_excluded -eq $suspect) {$account = $false}
    }
    $suspect = $null
    $user_excluded = $null
    $users_excluded_list = $null
    return $account
}
function is_account_disabled($status){
    $account_flag = $false
    if(($status -band 2) -eq 0x0002){$account_flag = $true}
    $status = $null
    Return $account_flag
}
 function primary_group_ID_name($ID){
    if     ($ID -eq 498){ $group_ID_name = "Enterprise Read-only Domain Controllers" }
    elseif ($ID -eq 500){ $group_ID_name = "Administrator" }
    elseif ($ID -eq 501){ $group_ID_name = "Guest" }
    elseif ($ID -eq 502){ $group_ID_name = "KRBTGT" }
    elseif ($ID -eq 512){ $group_ID_name = "Domain Admins" }
    elseif ($ID -eq 513){ $group_ID_name = "Domain Users" }
    elseif ($ID -eq 514){ $group_ID_name = "Domain Guests" }
    elseif ($ID -eq 515){ $group_ID_name = "Domain Computers" }
    elseif ($ID -eq 516){ $group_ID_name = "Domain Controllers" }
    elseif ($ID -eq 517){ $group_ID_name = "Domain Publishers" }
    elseif ($ID -eq 518){ $group_ID_name = "Schema Admins" }
    elseif ($ID -eq 519){ $group_ID_name = "Enterprise Admins" }
    elseif ($ID -eq 520){ $group_ID_name = "Policy Creator Owners" }
    elseif ($ID -eq 521){ $group_ID_name = "Read-only Domain Controllers" }
    elseif ($ID -eq 522){ $group_ID_name = "Cloneable Domain Controllers" }
    elseif ($ID -eq 526){ $group_ID_name = "Key Admins" }
    elseif ($ID -eq 527){ $group_ID_name = "Enterprise Key Admins" }
    elseif ($ID -eq 553){ $group_ID_name = "RAS and IAS Servers" }
    elseif ($ID -eq 571){ $group_ID_name = "Allowed RODC Password Replication group" }
    elseif ($ID -eq 572){ $group_ID_name = "Danied RODC Password replication group" }
    $ID = $null
    Return $group_ID_name
 }
 function convert_to_timestamp ($value) {
    if ($value -eq 0){
        $timestamp = $nc
    }elseif($value -eq $timestamp_zero){
        $timestamp = $nc
    }else{
        $fmt = "yyyyMMddHHmmss.f'Z'"
        $culture = ([CultureInfo]::InvariantCulture)
        $timestamp = [DateTimeOffset]::ParseExact($value, $fmt, $culture)
        $timestamp = [String]$timestamp.UtcDateTime.ToFileTimeUtc()
    }
    $nc = $null
    $value = $null
    $fmt = $null
    $culture = $null
    Return $timestamp
 }
 function check_timestamp ($value) {
    if ($value -eq 0) { $timestamp = $nc }
    elseif ($value -eq $timestamp_zero) { $timestamp = $nc }
    else{ $timestamp = $value }
    $nc = $null
    $value = $null
    $timestamp_zero = $null
 Return $timestamp
 } 
 function convert_to_date ($timestamp_to_date) {
    if (($timestamp_to_date -eq 0) -or ($timestamp_to_date -eq $nc)) {
        $timestamp = $nc
    }else{
        $timestamp = [DateTime]::FromFileTimeUtc($timestamp_to_date).ToString($date_format)
    }
    $nc = $null
    $timestamp_to_date = $null
 Return $timestamp
 }
 function convert_to_clock ($timestamp_to_date) {
    if (($timestamp_to_date -eq 0) -or ($timestamp_to_date -eq $nc)) {
        $days = $nc
    }else{
        $date_to_clock = [DateTime]::FromFileTimeUtc( $timestamp_to_date )
        $days = (New-TimeSpan -Start $date_to_clock -End $date).Days
    }
    $timestamp_to_date = $null
    $date_to_clock = $null
Return $days
}
### column names
$val01 = "SURNAME"
$val02 = "NAME"
$val03 = "USER NAME"
$val04 = "STATUS"
$val05 = "PR.GR.ID"
$val06 = "NAME"
$val07 = "WHEN CREATED"
$val08 = "CR.DAYS"
$val09 = "LAST CHANGE"
$val10 = "CH.DAYS"
$val11 = "LAST LOGON"
$val12 = "LOGON DAYS"
$val13 = "LAST LOGOFF"
$val14 = "LOGOFF DAYS"
$val15 = "PWD LAST SET"
$val16 = "PWD DAYS"
$val17 = "BAD PASSWORD"
$val18 = "B.PWD DAYS"
$val19 = "ACCOUNT EXPIRES"
$val20 = ""
$val21 = "script"
$val22 = "accound_disable"
$val23 = "RESERVED"
$val24 = "homedir_required"
$val25 = "lockout"
$val26 = "passwd_notreqd"
$val27 = "passwd_cant_change"
$val28 = "encrypted_text_pwd_allowed"
$val29 = "temp_duplicate_account"
$val30 = "normal_user"
$val31 = "RESERVED"
$val32 = "interdomain_trust_account"
$val33 = "workstation_trust_account"
$val34 = "server_trust_account"
$val35 = "RESERVED"
$val36 = "RESERVED"
$val37 = "dont_expire_password"
$val38 = "msn_logon_account"
$val39 = "smartcard_required"
$val40 = "trusted_for_delegation"
$val41 = "RESERVED"
$val42 = "domain_controller"
$val43 = "not_delegated"
$val44 = "use_des_key_only"
$val45 = "dont_req_preauth"
$val46 = "password_expired"
$val47 = "trusted_to_auth_for_delegation"
$val48 = "partial_secrets_account"
"$val01;$val02;$val03;$val04;$val05;$val06;$val07;$val08;$val09;$val10;$val11;$val12;$val13;$val14;$val15;$val16;$val17;$val18;$val19;$val20;$val21;$val22;$val23;$val24;$val25;$val26;$val27;$val28;$val29;$val30;$val31;$val32;$val33;$val34;$val35;$val36;$val37;$val38;$val39;$val40;$val41;$val42;$val43;$val44;$val45;$val46;$val47;$val48" | Out-File $tmp_csv -Encoding utf8
### main code
foreach ($user in $users) {
    if (is_account_excluded($user.sAMAccountName) -eq $true) {
        $user_account_control = [String]$user.userAccountControl    
    # account status
        $account_status = is_account_disabled($user_account_control)
        if ($account_status -eq $true) {$account_status = "disabled"}else{$account_status = "active"}
    # primary ID group
        $primary_group_ID = $user.primaryGroupID
        $group_ID_name = primary_group_ID_name($primary_group_ID)
    # when created
        $when_created = $user.whenCreated
        $when_created_timestamp = convert_to_timestamp($when_created)
        $when_created_date = convert_to_date($when_created_timestamp)
        $when_created_clok = convert_to_clock($when_created_timestamp)
    # last change
        $when_changed = $user.whenChanged
        $when_changed_timestamp = convert_to_timestamp($when_changed)
        $when_changed_date = convert_to_date($when_changed_timestamp)
        $when_changed_clock = convert_to_clock($when_changed_timestamp)
    # last logon
        $last_logon = $user.lastLogon
        $last_logon_timestamp = check_timestamp($last_logon)
        $last_logon_date = convert_to_date($last_logon_timestamp)
        $last_logon_clock = convert_to_clock($last_logon_timestamp)
        if(($last_logon_timestamp -eq $nc)-or($last_logon_date -eq $date_zero)){
            $last_logon_timestamp = $nc
            $last_logon_date = $nc
            $last_logon_clock = $nc
        }
    # last logoff
        $last_logoff = $user.lastLogoff
        $last_logoff_timestamp = check_timestamp($last_logoff)
        $last_logoff_date = convert_to_date($last_logoff_timestamp)
        $last_logoff_clock = convert_to_clock($last_logoff_timestamp)
        if(($last_logoff_timestamp -eq $nc)-or($last_logoff_date -eq $date_zero)){
            $last_logoff_timestamp = $nc
            $last_logoff_date = $nc
            $last_logoff_clock = $nc
        }
    # password last set
        $pwd_last_set = $user.pwdLastSet
        $pwd_last_set_timestamp = check_timestamp($pwd_last_set)
        $pwd_last_set_date = convert_to_date($pwd_last_set_timestamp)
        $pwd_last_set_clock = convert_to_clock($pwd_last_set_timestamp)
        if(($pwd_last_set_timestamp -eq $nc)-or($pwd_last_set_date -eq $date_zero)){
            $pwd_last_set_timestamp = $nc
            $pwd_last_set_date = $nc
            $pwd_last_set_clock = $nc
        }
    # bad password date
        $bad_password_time = $user.badPasswordTime
        $bad_password_timestamp = check_timestamp($bad_password_time)
        $bad_password_date = convert_to_date($bad_password_timestamp)
        $bad_password_clock = convert_to_clock($bad_password_timestamp)
        if(($bad_password_timestamp -eq $nc)-or($bad_password_date -eq $date_zero)){
            $bad_password_timestamp = $nc
            $bad_password_date = $nc
            $bad_password_clock = $nc
        }
    # account expires
        $account_expires = $user.accountExpires
        $account_expires_timestamp = check_timestamp($account_expires)
        $account_expires_date = convert_to_date($account_expires_timestamp)
        if(($account_expires_timestamp -eq $nc)-or($account_expires_date -eq $date_zero)){
            $account_expires_timestamp = $nc
            $account_expires_date = $nc
        }
    # account control flags   
        if(($user_account_control -band 1) -eq 0x0001)           {$script = $val_true}else{$script = $val_false}
        if(($user_account_control -band 2) -eq 0x0002)           {$accound_disable = $val_true}else{$accound_disable = $val_false}
        if(($user_account_control -band 4) -eq 0x0004)           {$reserved_A = $val_true}else{$reserved_A = $val_false}
        if(($user_account_control -band 8) -eq 0x0008)           {$homedir_required = $val_true}else{$homedir_required = $val_false}
        if(($user_account_control -band 16) -eq 0x0010)          {$lockout = $val_true}else{$lockout = $val_false}
        if(($user_account_control -band 32) -eq 0x0020)          {$passwd_notreqd = $val_true}else{$passwd_notreqd = $val_false}
        if(($user_account_control -band 64) -eq 0x0040)          {$passwd_cant_change = $val_true}else{$passwd_cant_change = $val_false}
        if(($user_account_control -band 128) -eq 0x0080)         {$encrypted_text_pwd_allowed = $val_true}else{$encrypted_text_pwd_allowed = $val_false}
        if(($user_account_control -band 256) -eq 0x0100)         {$temp_duplicate_account = $val_true}else{$temp_duplicate_account = $val_false}
        if(($user_account_control -band 512) -eq 0x0200)         {$normal_user = $val_true}else{$normal_user = $val_false}
        if(($user_account_control -band 1024) -eq 0x0400)        {$reserved_B = $val_true}else{$reserved_B=$val_false}
        if(($user_account_control -band 2048) -eq 0x0800)        {$interdomain_trust_account = $val_true}else{$interdomain_trust_account = $val_false}
        if(($user_account_control -band 4096) -eq 0x1000)        {$workstation_trust_account = $val_true}else{$workstation_trust_account = $val_false}
        if(($user_account_control -band 8192) -eq 0x2000)        {$server_trust_account = $val_true}else{$server_trust_account = $val_false}
        if(($user_account_control -band 16384) -eq 0x4000)       {$reserved_C = $val_true}else{$reserved_C = $val_false}
        if(($user_account_control -band 32768) -eq 0x8000)       {$reserved_D = $val_true}else{$reserved_D = $val_false}
        if(($user_account_control -band 65536) -eq 0x10000)      {$dont_expire_password = $val_true}else{$dont_expire_password = $val_false}
        if(($user_account_control -band 131072) -eq 0x20000)     {$msn_logon_account = $val_true}else{$msn_logon_account = $val_false}
        if(($user_account_control -band 262144) -eq 0x40000)     {$smartcard_required = $val_true}else{$smartcard_required = $val_false}
        if(($user_account_control -band 524288) -eq 0x80000)     {$trusted_for_delegation = $val_true}else{$trusted_for_delegation = $val_false}
        if(($user_account_control -band 528384) -eq 0x81000)     {$reserved_E = $val_true}else{$reserved_E = $val_false}
        if(($user_account_control -band 532480) -eq 0x82000)     {$domain_controller = $val_true}else{$domain_controller = $val_false}
        if(($user_account_control -band 1048576) -eq 0x100000)   {$not_delegated = $val_true}else{$not_delegated = $val_false}
        if(($user_account_control -band 2097152) -eq 0x200000)   {$use_des_key_only = $val_true}else{$use_des_key_only = $val_false}
        if(($user_account_control -band 4194304) -eq 0x400000)   {$dont_req_preauth = $val_true}else{$dont_req_preauth = $val_false}
        if(($user_account_control -band 83388608) -eq 0x800000)  {$password_expired = $val_true}else{$password_expired = $val_false}
        if(($user_account_control -band 16777216) -eq 0x1000000) {$trusted_to_auth_for_delegation = $val_true}else{$trusted_to_auth_for_delegation = $val_false}
        if(($user_account_control -band 67108864) -eq 0x04000000){$partial_secrets_account = $val_true}else{$partial_secrets_account = $val_false}
    # output   
        $val01 = $user.sn
        $val02 = $user.givenName
        $val03 = $user.userPrincipalName
        $val04 = $account_status
        $val05 = $primary_group_ID
        $val06 = $group_ID_name
        $val07 = $when_created_date
        $val08 = $when_created_clok
        $val09 = $when_changed_date
        $val10 = $when_changed_clock
        $val11 = $last_logon_date
        $val12 = $last_logon_clock
        $val13 = $last_logoff_date
        $val14 = $last_logoff_clock
        $val15 = $pwd_last_set_date
        $val16 = $pwd_last_set_clock
        $val17 = $bad_password_date
        $val18 = $bad_password_clock
        $val19 = $account_expires_date
        $val20 = ""
        $val21 = $script
        $val22 = $accound_disable
        $val23 = $reserved_A
        $val24 = $homedir_required
        $val25 = $lockout
        $val26 = $passwd_notreqd
        $val27 = $passwd_cant_change
        $val28 = $encrypted_text_pwd_allowed
        $val29 = $temp_duplicate_account
        $val30 = $normal_user
        $val31 = $reserved_B
        $val32 = $interdomain_trust_account
        $val33 = $workstation_trust_account
        $val34 = $server_trust_account
        $val35 = $reserved_C
        $val36 = $reserved_D
        $val37 = $dont_expire_password
        $val38 = $msn_logon_account
        $val39 = $smartcard_required
        $val40 = $trusted_for_delegation
        $val41 = $reserved_E
        $val42 = $domain_controller
        $val43 = $not_delegated
        $val44 = $use_des_key_only
        $val45 = $dont_req_preauth
        $val46 = $password_expired
        $val47 = $trusted_to_auth_for_delegation
        $val48 = $partial_secrets_account
        "$val01;$val02;$val03;$val04;$val05;$val06;$val07;$val08;$val09;$val10;$val11;$val12;$val13;$val14;$val15;$val16;$val17;$val18;$val19;$val20;$val21;$val22;$val23;$val24;$val25;$val26;$val27;$val28;$val29;$val30;$val31;$val32;$val33;$val34;$val35;$val36;$val37;$val38;$val39;$val40;$val41;$val42;$val43;$val44;$val45;$val46;$val47;$val48" |Out-File $tmp_csv -Append -Encoding utf8
    }
}