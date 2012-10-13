##
# $Id: exec.rb 14774 2012-02-21 01:42:17Z rapid7 $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

###
#
# Exec
# ----
#
# Executes an arbitrary command.
#
###
module Metasploit3

	include Msf::Payload::Single

	def initialize(info = {})
		super(merge_info(info,
			'Name'          => 'MSDOS Print String',
			'Version'       => '$Revision: 14774 $',
			'Description'   => 'Print a string',
			'Author'        => 'nemo',
			'License'       => MSF_LICENSE,
			'Platform'      => 'msdos',
			'Arch'          => ARCH_X86_16))

		# Register exec options
		register_options(
			[
			], self.class)
	end

	#
	# Dynamically builds the exec payload based on the user's options.
	#
	def generate_stage
		payload = "\xe8\x10\x00\x49\x74\x20\x77\x6f\x72\x6b\x65\x64\x2e\x2e\x2e\x0d\x0a\x24\x00\x5a\xb4\x09\xcd\x21\xcd\x20\xcc"
	end

end
