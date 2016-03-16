require 'msf/core'
require 'json'

class Metasploit3 < Msf::Auxiliary

    include Msf::Auxiliary::Report

    def initialize
        super(
            'Name'          => 'WiFi Pineapple Client Import',
            'Version'       => '$Revision: 1 $',
            'Description'   => 'Imports clients from WiFi Pineapple',
            'Author'        => 'WiFi Pineapple developers',
            'License'       => MSF_LICENSE
        )
        register_options([
            OptString.new('API_TOKEN', [true, 'A valid API key for the pineapple']),
            OptString.new('PINEAPPLE', [true, 'The local address of the pineapple', '172.16.42.1']),
            OptInt.new('PORT', [true, 'The port on which the web interface is running', 1471])
        ])
    end
    def run
        apiParams = {
            'module' => 'Clients',
            'action' => 'getClientData',
            'apiToken' => datastore['API_TOKEN']
        }
        client = Rex::Proto::Http::Client.new(datastore['pineapple'], port = datastore['port'])
        print_status("Connecting to pineapple")
        client.connect()
        request = client.request_raw({
            'rhost' => datastore['pineapple'],
            'rport' => datastore['port'],
            'uri' => '/api/',
            'method' => 'POST',
            'data' => JSON.generate(apiParams)
            })
        print_status("Requesting client data")
        response = client.send_recv(request)
        client.close()
        data = JSON.parse(response.body)
        if data['error']
            print_error("Error: %s" % data['error'])
            if data['error'] == 'Not Authenticated'
                print_error("Are you sure you correctly set API_TOKEN?")
            end
            return
        end
        if !data['clients']
            print_error("Got empty response")
            return
        end
        data = data['clients']
        if data['stations'].length == 0
            print_warning("There are currently no connected clients")
            return
        end
        data['stations'].keys.each do |mac|
            print_good("Importing: %s" % mac)
            ip = data['dhcp'][mac] ? data['dhcp'][mac][0] : data['arp'][mac]
            hostname = data['dhcp'][mac] ? data['dhcp'][mac][1] : nil
            oui = Rex::Oui::lookup_oui_company_name(mac)
            oui = (oui == 'UNKNOWN' ? nil : oui)
            ssid = data['ssids'][mac] ? data['ssids'][mac] : nil
            comment = nil
            report_host(:mac => mac, :host => ip, :state => Msf::HostState::Alive, :name => hostname)
            if ssid
                comment = "Associated to: %s" % ssid
                report_note(
                    :host => ip,
                    :type => "association_ssid",
                    :data => comment
                )
            end
            if oui
                report_note(
                    :host => ip,
                    :type => "mac_oui",
                    :data => oui
                )
            end
        end
    end
end
