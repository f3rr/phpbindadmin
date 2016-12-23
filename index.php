<?php

// Simple DNS Admin for BIND9
// nsupdate based Web Interface

// Settings

$zones = ['example.com']; // or place to zones.txt, new line/zone.
$types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SRV'];
$server = "10.62.0.16";
$keystring = "web-nsupdate a3t7gPAt3r6osCX7d4rW1k==";
$default_ttl = "3600";
$manage_reverse = true;  // Manage PTR with A, if we manage Reverse Zone.
$logging = true;
$auditlog = "bindadmin.log";
// Ldap
$ldap_enforce_login = true;
$ldap_server = "ldap01";
$ldap_bind_dn = "CN=LOGIN,OU=People,DC=example,DC=com"; // LOGIN will be replaced with user login
$ldap_base = "DC=example,DC=com";
$ldap_filter = '(&(objectClass=user)(cn=LOGIN))'; // LOGIN will be replaced with user login


date_default_timezone_set('Europe/Berlin');

// Settings end -- please do not change bellow

function init() {
  global $server, $zones;
  exec("which nsupdate", $output, $exit);
  if ($exit) { echo "nsupdate command not found."; die(); };
  exec("which dig", $output, $exit);
  if ($exit) { echo "dig command not found."; die(); };
  if (file_exists('zones.txt')) { $myfile = fopen("zones.txt", "r") or die("Unable to open file!"); $zones_s = fread($myfile,filesize("zones.txt"));  $zones_t = preg_replace('/\s+/', ' ', $zones_s); $add_zones = explode(' ',$zones_t); fclose($myfile); $zones = array_filter(array_merge($zones, $add_zones)); }
  $query = "";
  session_start();
}

function log_this($text) {
  global $now, $username, $auditlog, $logging;
  if ($logging) {
    $log_text = "[".$now."][".$username."]: ".$text."\n";
    file_put_contents($auditlog, $log_text, FILE_APPEND | LOCK_EX);
  }
}

function head() {
  if ($_SESSION['authenticated']) { $user_btn = '<li><a href="'.$_SERVER["SCRIPT_NAME"].'/logout"><span class="glyphicon glyphicon-log-out"></span> Logout</a></li>'; } else { $user_btn = '<li><a href="'.$_SERVER["SCRIPT_NAME"].'/login"><span class="glyphicon glyphicon-log-in"></span> Login</a></li>'; }
  $head = '
    <!DOCTYPE html>
    <html>
      <head>
        <title>PHP Bind Admin</title>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1">
        <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.css">
        <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.1.1/jquery.js"></script>
        <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.js"></script>
        <script src="https://raw.githubusercontent.com/tavicu/bs-confirmation/master/bootstrap-confirmation.js"></script>
    </head>';
  $body = '
    <body>
      <nav class="navbar navbar-inverse">
        <div class="container-fluid">
          <div class="navbar-header">
            <a class="navbar-brand" href="'.$_SERVER["SCRIPT_NAME"].'">Bind Admin</a>
          </div>
          <ul class="nav navbar-nav">
            <li class=""><a href="'.$_SERVER["SCRIPT_NAME"].'">Home</a></li>
            <li class=""><a href="'.$_SERVER["SCRIPT_NAME"].'/zones">Zones</a></li>
          </ul>
          <ul class="nav navbar-nav navbar-right">'.$user_btn.'
          </ul>
        </div>
      </nav>';
  echo $head . $body;
}


// Listing all zones
function zones() {
  global $zones, $server, $ldap_enforce_login;
  if ((!$_SESSION['authenticated']) AND ($ldap_enforce_login)) { echo '<div class="alert alert-danger"><strong>Permission Denied.</strong> <a href="'.$_SERVER["SCRIPT_NAME"].'/login">Login</a> first</div>'; die(); }
  $c = "";
  $pre = '<div class="container"><h3>Zones</h3><div class="list-group">';
  foreach($zones as $zone) { $o = ""; exec("dig @".$server." ".$zone." axfr | grep IN |grep -v SOA | wc -l", $o); $l = $o[0]; $c .= '<a href="'.$_SERVER["SCRIPT_NAME"].'/zone/' . $zone . '" class="list-group-item">' . $zone . '<span class="badge">'.$l.'</span></a>'; }
  $post='</div></div>';
  echo $pre.$c.$post;
}



// IP
function has_reverse($host,$ip) {
  if (get_rev($ip)[0] == $ip) { return false; } else { if (is_valid_domain_name(get_rev($ip)[0])) { return true;} else { return false; } }
}

// Returns with IPs rerverse record
function get_rev($ip) {
  global $server;
  exec("dig @".$server." -x ".$ip." +short", $output, $exit);
  return $output[0];
}

// Returns IP from FQDN
function get_ip($fqdn) {
  global $server;
  exec("dig @".$server." ".$fqdn." +short | tail -1", $output, $exit);
  return $output[0];
}

// Validate IP
function is_ip($ip) {
if (filter_var($ip, FILTER_VALIDATE_IP)) { return true; } else { return false; };
}


function check_cname($cname,$zone) {
  global $server;
  exec("dig @".$server." ".$cname." +short | tail -1", $output, $exit);
  if (is_ip($output[0])) { return true; } else { return false; }
}

// Checks if $host has the right reverse
function check_ptr($host,$target) {
  global $server;
  $ip = explode('.', $host)[3].".".explode('.', $host)[2].".".explode('.', $host)[1].".".explode('.', $host)[0];
  exec("dig @".$server." ".$target." +short | tail -1", $output, $exit);
  if ($output[0] == $ip) { return true; } else { return false; }
}

// Liste records in $zone
function records($zone) {
  global $server, $types, $default_ttl, $ldap_enforce_login;
  if ((!$_SESSION['authenticated']) AND ($ldap_enforce_login)) { echo '<div class="alert alert-danger"><strong>Permission Denied.</strong> <a href="'.$_SERVER["SCRIPT_NAME"].'/login">Login</a> first</div>'; die(); }
  $add_message = "";
  $add_ttl = $default_ttl;
  if (isset($_POST['add_record'])) { $add_ttl = $_POST['ttl']; $add_record = add_record(); if ($add_record['ok']) { $add_message = '<div class="alert alert-success"><strong>Success!</strong> ';} else { $add_message = '<div class="alert alert-danger"><strong>Error!</strong><ul>'; } foreach($add_record['message'] as $m) { $add_message .= "<li>".$m."</li>"; } $add_message .= "</ul></div>"; }
  if (isset($_POST['delete'])) { $del_record = delete_record(); if ($del_record['ok']) { $del_message = '<div class="alert alert-success"><strong>Success!</strong> '; } else { $del_message = '<div class="alert alert-danger"><strong>Error!</strong><ul>'; } foreach($del_record['message'] as $m) { $del_message .= "<li>".$m."</li>"; } $del_message .= "</ul></div>";  }
  exec("dig @".$server." ".$zone." axfr | grep IN", $output, $exit);
  if ($exit) { die("Can't query zone $zone, webserver in allow-transfer list?"); }
  if ((!isset($zone)) OR ( empty($zone))) { die("Zone not set or empty"); }
  $soa_e = "dig @".$server." ".$zone." SOA| grep SOA | tail -1";
  exec($soa_e,$soa_o,$soa_er);
  $s_tmp = preg_replace('/\s+/', ' ', $soa_o[0]);
  $soa = explode(' ', $s_tmp);
  $records = [];
  $i = 0;
  $add_options = "";
  if (strpos($zone, 'in-addr.arpa') !== false) {
      $t2 = ['PTR', 'NS'];
  } else {
      $t2 = $types;
  }
  foreach($t2 as $type) { $add_options .= "<option>".$type."</option>"; }
  foreach($output as $e) {
    $entry = preg_replace('/\s+/', ' ', $e);
    $record['host'] = explode(' ', $entry)[0];
    $record['ttl'] = explode(' ', $entry)[1];
    $record['type'] = explode(' ', $entry)[3];
    $record['target'] = explode(' ', $entry)[4];
    $record['status'] = 'class="active"';
    $record['info_icon'] = "glyphicon-info-sign";
    if ($record['type'] == "PTR") { if (check_ptr($record['host'], $record['target'])) { $record['status'] = 'class="success"'; } else { $record['info_icon'] = "glyphicon-exclamation-sign"; $record['status'] = 'class="danger"'; $record['messages'][] = "PTR mssing A"; } }
    if ($record['type'] == "CNAME") { if (check_cname($record['host'], $zone)) { $record['status'] = 'class="success"'; $dip = get_ip($record['target']); $record['messages'][] = "CNAME looks OK. Destination: ".$dip; } else { $record['info_icon'] = "glyphicon-exclamation-sign"; $record['status'] = 'class="danger"'; $record['messages'][] = "Cant resolve destination"; } }
    if ($record['type'] == "A") { if (has_reverse($record['host'],$record['target'])) { if (get_rev($record['target']) == $record['host']) { $record['messages'][] = "A has PTR"; $record['status'] = 'class="success"'; } else { $record['status'] = 'class="warning"'; $record['messages'][] = "Target PTR differs"; } }else { $record['info_icon'] = "glyphicon-exclamation-sign"; $record['status'] = 'class="danger"'; $record['messages'][] = "Destination IP has no PTR"; } }
    if (!empty($record['messages'])) { foreach($record['messages'] as $m) { $record['info_text'] = "* ".$m; }  }
    if ($record['type'] != "SOA") { $records[$i] = $record; }
    $i++;
  }
  $pre = '
    <div class="container">
     <div class="panel-group">
      <div class="panel panel-default">
      <div class="panel-heading"><a data-toggle="collapse" href="#collapse1">Add Record</a></div>
      <div class="panel-body panel-collapse" id="collapse1">
      <form class="form-inline" method="POST">'.$add_message.'
      <input type="hidden" name="add_record" />
      <input type="hidden" name="zone" value="'.$zone.'" />
      <table class="table"><thead><tr><th>Host</th><th>TTL</th><th>Type</th><th>Target</th></tr></thead>
      <tr><td><div class="input-group"><input type="text" class="form-control" id="host" placeholder="host" name="host"><span class="input-group-addon">.'.$zone.'.</span></div>  </td><td><input type="text" class="form-control" id="ttl" name="ttl" value="'.$add_ttl.'"></td><td><select class="form-control" id="type" name="type">'.$add_options.'</select></td><td><input type="text" class="form-control" id="target" name="target" placeholder="Target">  </td></tr>
      </table>
      <button type="submit" class="btn btn-primary active">Add Record</button>
      </form>
      </div>
      </div>
      <div class="panel panel-default">
      <div class="panel-heading"><a data-toggle="collapse" href="#collapse2">Zone: '.$zone.'</a></div>
      <div class="panel-body panel-collapse" id="collapse2">'.$del_message.'
      <p><small>You are current editing zone '.$soa[0].'.</small></p>
      <h5>Primary NS: <small>'.$soa[4].'</small></h5>
      <h5>Contact E-Mail: <small>'.$soa[5].'</small></h5>
      <h5>Revision Number: <small>'.$soa[6].'</small></h5>
      <h5>Refresh: <small>'.$soa[7].'</small></h5>
      <h5>Retry: <small>'.$soa[8].'</small></h5>
      <h5>Expire: <small>'.$soa[9].'</small></h5>
      <h5>Minimum: <small>'.$soa[10].'</small></h5>
      <table class="table">
        <thead>
          <tr>
            <th>Host</th>
            <th>TTL</th>
            <th>Type</th>
            <th>Target</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>';
    $c = '';
  foreach($records as $r) {
    $c .= '<tr '.$r["status"].'><td>'.$r["host"].'</td><td>'.$r["ttl"].'</td><td>'.$r["type"].'</td><td>'.$r["target"].'</td><td>
      <div class="btn-group btn-group-sm" role="group" aria-label="...">
        <form class="form-horizontal" method="POST">
        <input type="hidden" name="host" value="'.$r['host'].'" />
        <input type="hidden" name="ttl" value="'.$r['ttl'].'" />
        <input type="hidden" name="type" value="'.$r['type'].'" />
        <input type="hidden" name="target" value="'.$r['target'].'" />
        <button type="submit" class="btn btn-default"><span class="glyphicon glyphicon-pencil" aria-hidden="true" name="edit"></span></button>
        <button type="button" class="btn btn-default" id="infobtn" data-toggle="tooltip" title="'.$r['info_text'].'" data-placement="top"> <span class="glyphicon '.$r['info_icon'].'" aria-hidden="true"></span></button>
        <button type="submit" class="btn btn-default" onclick="return confirm(\'Are you sure you want to delete this item?\');" name="delete"><span class="glyphicon glyphicon-trash" aria-hidden="true"></span></button>
        </form>
      </div>
      </td></tr>';
  }
  $post = '</tbody></table></div></div></div></div><script type="text/javascript">$(function () { $(\'[data-toggle="tooltip"]\').tooltip() })</script>';
echo $pre.$c.$post;
}

// Validate FQDN
function is_valid_domain_name($domain_name)
{
    return (preg_match("/^([a-z\d](-*[a-z\d])*)(\.([a-z\d](-*[a-z\d])*))*$/i", $domain_name) //valid chars check
            && preg_match("/^.{1,253}$/", $domain_name) //overall length check
            && preg_match("/^[^\.]{1,63}(\.[^\.]{1,63})*$/", $domain_name)   ); //length of each label
}

// Deletes a record.
function delete_record() {
  global $keystring, $server, $manage_reverse;
  $host = $_POST['host'];
  $ttl = $_POST['ttl'];
  $type = $_POST['type'];
  $target = $_POST['target'];
  $zone = $_POST['zone'];
  $ret['ok'] = true;
  $file[] = "server ".$server;
  $file[] = "key ".$keystring;
  $file[] = "update delete ".$host." ".$type;
  if (($manage_reverse) AND ($type == "A")) { $rr = join('.',array_reverse(explode('.', $target))).".in-addr.arpa."; if ((rr_by_us($rr)) AND (get_rev($target) == $host)) { $file[] = ''; $file[] = "update delete ".$rr." PTR"; log_this($rr." IN PTR ".$host." deleted"); } }
  $file[] = "send";
  $file[] = "";
  $nsupdate_file = substr(str_shuffle(str_repeat('0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', mt_rand(1,10))),1,6);
  $fp = fopen($nsupdate_file, 'w') or die("Unable to open file!");
  fwrite($fp, join("\n", $file));
  fclose($fp);
  $c = "nsupdate -v ".$nsupdate_file." 2>&1";
  exec($c, $o, $e);
  log_this($host." IN ".$type." ".$target." deleted");
  unlink($nsupdate_file);
  foreach($o as $ent) { $ret['message'][] = $ent; }
  if ($e) { $ret['ok'] = false; };
  if ($ret['ok']) { $ret['message'][] = $host." deleted successful";  }
  return $ret;
}

// Check if reverse zone is managed by us.
function rr_by_us($rr) {
  global $zones;
  $m = false;
  foreach($zones as $z) {
    if (strpos($rr, $z) !== false) {
      $m = true;
    }
  }
  return $m;
}

// Adds a record
function add_record() {
  global $keystring, $server, $manage_reverse;
  $host = $_POST['host'];
  $ttl = $_POST['ttl'];
  $type = $_POST['type'];
  $target = $_POST['target'];
  $zone = $_POST['zone'];
  $ret['ok'] = true;
  if (empty($host)) { $ret['ok'] = false; $ret['message'][] = "Host Empty"; $ret['field'][] = "host"; }
  if (empty($ttl)) { $ret['ok'] = false; $ret['message'][] = "TTL Empty"; $ret['field'][] = "ttl"; }
  if (empty($type)) { $ret['ok'] = false; $ret['message'][] = "Type Empty"; $ret['field'][] = "type"; }
  if (empty($target)) { $ret['ok'] = false; $ret['message'][] = "Target Empty"; $ret['field'][] = "target"; }
  if ($ret['ok']) {
  $fixed_target = $target;
  switch($type) {
    case "A":
     if (!filter_var($target, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) { $ret['ok'] = false; $ret['message'][] = "Target is not a valid IPv4 Address"; $ret['field'][] = "target"; }
     if ($manage_reverse) { $rr = join('.',array_reverse(explode('.', $target))).".in-addr.arpa."; if ((rr_by_us($rr)) AND (get_rev($target) == "")) { $reverse_record = $rr; } }
     break;
    case "AAAA":
     if(!filter_var($target, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) { $ret['ok'] = false; $ret['message'][] = "Target is not a valid IPv6 Address"; $ret['field'][] = "target"; }
     break;
    case "NS":
     if (!is_valid_domain_name($target)) { $ret['ok'] = false; $ret['message'][] = "Target is not a valid FQDN"; }
     break;
    case "CNAME":
     if (!is_valid_domain_name($target)) { $ret['ok'] = false; $ret['message'][] = "Target is not a valid FQDN"; }
     break;
  } }
  $add_server = "server ".$server;
  $add_key = "key ".$keystring;
  $add_reverse = "prereq nxdomain ".$reverse_record."\nupdate add ".$reverse_record." ".$ttl." PTR ".$host.".".$zone.".";
  $add_line = "update add ".$host.".".$zone.". ".$ttl." ".$type." ".$fixed_target;
  $add_zone = "zone ".$zone.".";
  $nsupdate_template = [$add_server, $add_key, $add_line];
  if (isset($reverse_record)) { $nsupdate_template[] = ''; $nsupdate_template[] = $add_reverse; log_this($reverse_record." IN PTR ".$host.".".$zone.". added.");}
  $nsupdate_template[] = 'send';
  $nsupdate_template[] = '';
  $nsupdate_file = substr(str_shuffle(str_repeat('0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', mt_rand(1,10))),1,6);
  $fp = fopen($nsupdate_file, 'w') or die("Unable to open file!");
  fwrite($fp, join("\n", $nsupdate_template));
  fclose($fp);
  $c = "nsupdate -v ".$nsupdate_file." 2>&1";
  exec($c, $o, $e);
  log_this($host.".".$zone.". IN ".$type." ".$target." added.");
  unlink($nsupdate_file);
  foreach($o as $ent) { $ret['message'][] = $ent; }
  if ($e) { $ret['ok'] = false; };
  if ($ret['ok']) { $ret['message'][] = $host.".".$zone." added successful";  }
  return $ret;

}

// Home Screen. Print log
function homepage() {
  global $auditlog;
  $l = array_reverse(array_slice(file($auditlog), -15));
  $out = "";
  foreach($l as $line) {
    $date_user = explode(': ', $line)[0];
    $content = explode(': ', $line)[1];
    $out .= '<div class="panel panel-default"><div class="panel-heading">'.$date_user.'</div><div class="panel-body">'.$content.'</div></div>';
  }
  $pre = '<div class="container"><div class="row"><div class="col-sm-4"></div><div class="col-sm-4"><div class="panel-group">'.$out.'</div></div></div></div>';
  echo $pre;
}

//// User related

// Login Form
function login_form() {
  if ($_SESSION['authenticated'] == true) {
    // Go somewhere secure
    header('Location: '.$_SERVER["SCRIPT_NAME"]);
  } else {
    if (!empty($_POST)) {
          $username = empty($_POST['username']) ? null : $_POST['username'];
          $password = empty($_POST['password']) ? null : $_POST['password'];
          $logged_in = check_user($username, $password);
          if ($logged_in) {
              log_this("User ".$username." logged in.");
              $_SESSION['authenticated'] = true;
              $_SESSION['username'] = $username;
              // Redirect to your secure location
              header('Location: '.$_SERVER["SCRIPT_NAME"]);
              return;
          }
    }
    if (isset($_POST['username'])) { $pupup_message = '<div class="alert alert-danger"><strong>Failed!</strong> Wrong Username or Password!</div>'; $olduser = ' value="'.$_POST['username'].'"'; }
    $form = '<div class="container"><div class="row centered-form"><div class="col-xs-12 col-sm-8 col-md-4 col-sm-offset-2 col-md-offset-4"><div class="panel panel-default"><div class="panel-heading"><h3 class="panel-title"><span class="glyphicon glyphicon-user"></span> Login <small>... and do it!</small></h3></div><div class="panel-body">'.$pupup_message.'<form role="form" method="post"><div class="form-group"><input type="text" name="username" id="username" class="form-control input-sm" placeholder="Username"'.$olduser.'></div><div class="form-group"><input type="password" name="password" id="password" class="form-control input-sm" placeholder="Password"></div><input type="submit" value="Login" class="btn btn-info btn-block"></form></div></div></div></div></div>';
    head();
    echo $form;
  }
}


// Login logic
function check_user($username, $password) {
  global $ldap_server, $ldap_bind_dn, $ldap_base, $ldap_filter;
  $ldap = ldap_connect($ldap_server) or die("cant connect ldap");
  ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3);
  ldap_set_option($ldap, LDAP_OPT_REFERRALS, 0);
  $full_username = str_replace('LOGIN',$username,$ldap_bind_dn);
  if ($ldap) {
    $bind = ldap_bind($ldap, $full_username, $password);
    if ($bind) {
      $filter = str_replace('LOGIN',$username,$ldap_filter);
      $result = ldap_search($ldap, $ldap_base,$filter);
      $info = ldap_get_entries($ldap, $result);
      if ($info['count'] == 1) {
        return true;
      } else {
        return false;
      }
    } else {
      return false;
    }
  }
}



/// Core

// URL Route
function router() {
  $menu = explode('/', substr($_SERVER['PHP_SELF'], strlen($_SERVER['SCRIPT_NAME'])))[1];
  $zone = explode('/', substr($_SERVER['PHP_SELF'], strlen($_SERVER['SCRIPT_NAME'])))[2];
  if (!isset($menu)) { $menu = "home"; }
  switch($menu) {
    case "zones":
      head();
      zones();
      break;
    case "zone":
      head();
      records($zone);
      break;
    case "login":
      login_form();
      break;
    case "logout":
      log_this("User ".$username." logged out.");
      $_SESSION['authenticated'] = false;
      header('Location: '.$_SERVER["SCRIPT_NAME"]);
      break;
    default:
      head();
      homepage();
      echo "Home";
      break;
  }

};
$now = date('m/d/Y h:i:s a', time());
$version = "0.1"
init();
if ($_SESSION['authenticated']) { $username = $_SESSION['username']; }
router();
echo "OK";
?>

