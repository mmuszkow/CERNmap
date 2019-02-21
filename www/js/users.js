// why no online search?
// because there is no official API for that
// Android maps uses m.web.cern.ch (Sebastian'a API?)
// also the results doesn't contain the phones prefixes

var db = null;
var is_running = false;

function users_db_init() {
    db = openDatabase('xldap', '1.0', 'Offline CERN contacts storage', 10*1024*1024);
    db.transaction(function(t) {
        t.executeSql('CREATE TABLE IF NOT EXISTS users (givenName,surname,mail,office,department,phone,mobile)');
    });
}

function sanitize(val) {
    if(typeof(val) === 'undefined')
        return null;
    return val
        .replace(/&/g, '&amp;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}

function download_users() {
    if(is_running)
        return;
    is_running = true;

    var pbar = document.getElementById('ldap-progress');
    pbar.style.visibility = 'visible';
    pbar.value = 0;

    var xldap = new LdapClient('xldap.cern.ch', 389,
        function () { // on bind succ
            db.transaction(function(t) { t.executeSql('DELETE FROM users'); });
            xldap.search(
                'ou=Users,ou=Organic Units,dc=cern,dc=ch',
                [['physicalDeliveryOfficeName', '*'], ['cernAccountType', 'Primary']],
                ['givenName', 'sn', 'mail', 'physicalDeliveryOfficeName', 'department', 'telephoneNumber', 'mobile'],
                function(data, is_last) {
                    db.transaction(function(t) {
                        for(var i=0; i<data.length; i++) {
                            var u = data[i];
                            if(typeof(u.physicalDeliveryOfficeName) !== 'undefined') {
                                t.executeSql('INSERT INTO users (givenName,surname,mail,office,department,phone,mobile) values (?,?,?,?,?,?,?)',
                                    [sanitize(u.givenName), sanitize(u.sn), sanitize(u.mail), sanitize(u.physicalDeliveryOfficeName), 
                                    sanitize(u.department), sanitize(u.telephoneNumber), sanitize(u.mobile)]);
                            }
                        }
                        pbar.value += data.length;
                    });
                    if(is_last) {
                        localStorage.users_list = 'present';
                        xldap.unbind();
                        alert('Synchronizing CERN personnel done');
                        pbar.style.visibility = 'hidden';
                        is_running = false;
                    }
                }
            );
        },
        function (errMsg) {
            if(errMsg.indexOf('Connection reset by peer') > 0)
                errMsg = 'Connection with the server has been lost, this is usually caused by poor quality of WiFi connection.';
            else if(errMsg.indexOf('Socket is not connected') > 0)
                errMsg = 'Please ensure you are connected to CERN WiFi network.';
            else if(errMsg.indexOf('Connection to xldap.cern.ch failed') > 0)
                errMsg = 'Connection to CERN users directory has failed. Please ensure you are connected to CERN WiFi network.';
            errMsg = 'Error occured, the CERN personnel list will be incomplete. ' + errMsg;
            alert(errMsg);
            pbar.style.visibility = 'hidden';
            is_running = false;
            localStorage.users_list = 'error';
        }
    );
};

function find_user(text, respCallback) {
    if(localStorage.users_list === 'present') {
        db.readTransaction(function(t) {
            t.executeSql(
                'SELECT givenName,surname,mail,office,department,phone,mobile FROM users WHERE surname LIKE ? OR givenName LIKE ? LIMIT 5', 
                [text+'%',text+'%'], function(t, r) {
                    var formatted = [];
                    for(var i=0; i<r.rows.length; i++) {
                        if(r.rows.item(i).office !== null) {
                            var bNo = r.rows.item(i).office.split(' ')[0];
                            if(typeof(buildings[bNo]) !== 'undefined') {
                                var user = r.rows.item(i);
                                var html = '<b>'+user.givenName+' '+user.surname+'</b> ('+user.department+')<br>';
                                html += '<a href="mailto://'+user.mail+'">'+user.mail+'</a><br>';
                                html += 'Office: '+user.office+'<br>';
                                if(user.phone !== null)
                                    html += 'Phone: <a href="tel:'+user.phone +'">'+user.phone+'</a><br>';
                                if(user.mobile !== null)
                                    html += 'Mobile: <a href="tel:'+user.mobile +'">'+user.mobile+'</a><br>';
                                formatted.push({title: user.givenName+' '+user.surname, loc: buildings[bNo], popup: html});
                            }
                        }
                    }
                    respCallback(formatted);
                }, function(t, e) {
                    alert('Cant read the db: ' + e.message);
            })
        });
    } else {
        respCallback([]);
        alert('To use this functionality, go to "About" link on the bottom of map page and '
            +'download the CERN personnel list. This needs to be done inside CERN network.');
    }
}
