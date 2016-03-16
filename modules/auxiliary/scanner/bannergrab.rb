=begin
I couldn't find a banner grabbing module I liked anywhere,
so I made one. Much of this code is based off of the already
existing auxiliary/scanner/portscan/tcp modules.

For more of my projects, see https://github.com/735tesla
=end
require 'msf/core'
require 'strscan'
class Metasploit3 < Msf::Auxiliary
    include Msf::Exploit::Remote::Tcp
    include Msf::Auxiliary::Scanner
    include Msf::Auxiliary::Report
    def initialize
        super(
            'Name'          => 'TCP Banner Grabbing Module',
            'Version'       => '$Revision: 1 $',
            'Description'   => 'TCP Banner grabbing script',
            'Author'        => 'Tesla',
            'License'       => MSF_LICENSE
        )
        register_options(
            [
                OptString.new('PORTS', [true, "Ports to scan (e.g. 22-25,80,110-900)", "20-25,80,110,443,5900,8080,8443"]),
                OptInt.new('TIMEOUT', [true, "The socket connect timeout in milliseconds", 1000]),
                OptInt.new('CONCURRENCY', [true, "The number of concurrent ports to check per host", 10]),
            ], self.class)

        deregister_options('RPORT')
    end

    def run_host(ip)
        # Try to resolve the hostname via reverse dns
        @the_hostname = ''
        @the_hostname = `nslookup #{ip} | grep 'name = ' | awk '{print $4}' | sed 's/\.$//g'`.sub("\n","") if Rex::Socket::is_ipv4?(ip) == true
        # If we couldn't resolve the hostname, just set it to the ip
        @the_hostname = ip if @the_hostname == ''
        timeout = datastore['TIMEOUT'].to_i
        ports = Rex::Socket.portspec_to_portlist(datastore['PORTS'])
        if ports.empty?
            print_error("You either didn't specify any ports, or specified them incorrectly.")
            raise Msf::OptionValidateError.new(['PORTS'])
        end
        while ports.length>0
            the_threads=[]
            responses=[]
            begin
                1.upto(datastore['CONCURRENCY']) do
                    current_port = ports.shift
                    break if not current_port
                    the_threads << framework.threads.spawn("#{self.refname}-scanning-#{ip}:#{current_port}", false, current_port) do |port|
                        begin
                            sock = connect(false,
                                {
                                    'RHOST' => ip,
                                    'RPORT' => port,
                                    'ConnectTimeout' => (timeout / 1000.0)
                                }
                            )
                            print_good("TCP port #{port} on #{ip} is open, attemting to gather info")
                            banner = ''
                            begin
                                banner = grab_banner(sock, current_port)
                            rescue ::Exception => e
                                print_error("Encountered an unexpected exception whilst attempting to grab a banner from port #{port} on #{ip}:")
                                print_error("#{e.class}\t#{e}\t#{e.backtrace}")
                            end
                            responses << [ip,port,banner]
                        rescue ::Rex::ConnectionRefused
                            vprint_status("TCP port #{port} on #{ip} is closed :(")
                        rescue ::Rex::ConnectionError, ::IOError, ::Timeout::Error
                        rescue ::Rex::Post::Meterpreter::RequestError
                        rescue ::Interrupt
                            raise $!
                        rescue ::Exception => e
                            print_error("Encountered an unexpected exception whilst attempting to connect to #{ip} on port #{port}:")
                            print_error("#{e.class}\t#{e}\t#{e.backtrace}")
                        ensure
                            disconnect(sock) rescue nil
                        end
                    end
                end
                the_threads.each {|x| x.join }
                rescue ::Timeout::Error
                ensure
                    the_threads.each {|the_thread| the_thread.kill rescue nil}
                end
            responses.each do |response|
                report_service( :host => response[0], :port => response[1], :state => "open", :info => response[2] )
            end
        end
    end

    SERVICES = {
        20 => :negotiate_ftp,
        21 => :negotiate_ftp,
        22 => :negotiate_ssh,
        23 => :negotiate_telnet,
        25 => :negotiate_smtp,
        80 => :negotiate_http11,
        443 => :negotiate_https,
        8080 => :negotiate_http11,
        8443 => :negotiate_https,
    }

    def grab_banner(sock, port)
        print_status("Grabbing banner on port #{port}")
        ret_banner = send SERVICES[port], sock if SERVICES[port] != nil
        ret_banner = negotiate_generic(sock) if SERVICES[port] == nil
        return clean_response(ret_banner)
    end

    def negotiate_ftp(sock)
        resp = "USER anonymous\r\n" # Username
        resp << "PASS mozilla@mozilla.org\r\n" # Password (no this is not my actual email)
        resp << "PASV\r\n" # Enter PASV mode
        resp << "HELP\r\n" # List available commands
        resp << "PWD\r\n" # Get current directory
        resp << "LIST\r\n" # List files in current directory
        resp << "LIST /\r\n" # Try to list files in root directory
        sock.put(resp)
        return sock.recv(4096)
    end

    # Begin code stolen from https://github.com/wconrad/ftpd/blob/master/lib/ftpd/telnet.rb
    module Codes
        IAC  = 255.chr    # 0xff
        DONT = 254.chr    # 0xfe
        DO   = 253.chr    # 0xfd
        WONT = 252.chr    # 0xfc
        WILL = 251.chr    # 0xfb
        IP   = 244.chr    # 0xf4
        DM   = 242.chr    # 0xf2
    end
    include Codes
    # End stolen code
    # Heavily based off of H. D. Moore's banner-plus.nse
    def negotiate_telnet(sock)
        response = sock.recv(1024)
        resp = ""
        index = 0
        (0..20).each do
            # If the response is IAC (Interpret as Command)
            index = response.index(IAC, index)
            break if not index
            # The option type is the character after IAC
            opttype = response[index+1]
            # The option is the character after that
            opt = response[index+2]
            # If the option type is WILL or WONT, we respond with DONT
            if [WILL, WONT].index(opttype)!=nil
                opttype = DONT
            # If the option type is DO or DONT, we respond with WONT
            elsif [DO, DONT].index(opttype)!=nil
                opttype = WONT
            end
            # Our response is [IAC] + [OPTION TYPE] + [OPTION]
            resp << IAC
            resp << opttype
            resp << opt
            index += 1
        end
        sock.put(resp)
        response += sock.recv(1024)
    end

    def negotiate_ssh(sock)
        resp = sock.recv(1024)
        sock.put(resp)
        resp << sock.recv(1024)
        return resp
    end

    def negotiate_smtp(sock)
        sock.put("EHLO #{@the_hostname}\r\n")
        return sock.recv(1024)
    end

    def negotiate_http11(sock)
        # GET /
        req = "GET / HTTP/1.1\r\n"
        # The hostname we got from reverse dns (may be incorrect)
        req << "Host: #{@the_hostname}\r\n"
        # Accept anything
        req << "Accept: */*\r\n"
        # Close the connection when we're done
        req << "Connection: close\r\n"
        # Don't cache anything
        req << "Cache-Control: no-cache\r\n"
        # We are firefox
        req << "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:12.0) Gecko/20100101 Firefox/12.0\r\n"
        # End of request
        req << "\r\n"
        sock.put(req)
        resp =  sock.recv(212944)
        return resp
    end

    def negotiate_https(sock)
        # Taken from vmauthd_version
        ctx = OpenSSL::SSL::SSLContext.new(:SSLv3)
        key = OpenSSL::PKey::RSA.new(1024)
        ctx.key = key
        ctx.session_id_context = Rex::Text.rand_text(16)
        lsslsock = OpenSSL::SSL::SSLSocket.new(sock, ctx)
        lsslsock.connect
        sock.extend(Rex::Socket::SslTcp)
        sock.sslsock = lsslsock
        sock.sslctx  = ctx
        cert = sock.peer_cert
        print_status("Using certificate: #{cert.subject.to_s}")
        # GET /
        req = "GET / HTTP/1.1\r\n"
        # Host is www (because I'm too lazy to do any fancy reverse DNS resolution)
        req << "Host: www\r\n"
        # Accept anything
        req << "Accept: */*\r\n"
        # Close the connection when we're done
        req << "Connection: close\r\n"
        # Don't cache anything
        req << "Cache-Control: no-cache\r\n"
        # We are firefox
        req << "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64; rv:12.0) Gecko/20100101 Firefox/12.0\r\n"
        # End of request
        req << "\r\n"
        sock.put(req)
        return sock.recv(212944)
    end

    def negotiate_generic(sock)
        return sock.recv(4096)
    end

    def clean_response(s)
        valid_char = /[0-9A-Za-z`~!@\#$%^&*()-_=+\[{\]}|\\;:'",<.>\/? ]/
        sanitized = ''
        s.each_char do |c|
            if c.match(valid_char) != nil
                sanitized << c.encode("utf-8")
            elsif c == "\x0a"
                sanitized << "\\n"
            elsif c == "\x0d"
                sanitized << "\\r"
            else
                sanitized << ("\\x" << c.unpack("H*")[0]).encode("utf-8")
            end
        end
        return sanitized
    end
end