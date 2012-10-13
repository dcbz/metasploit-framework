##
# $Id: xor.rb 14774 2012-02-21 01:42:17Z rapid7 $
##

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##


require 'msf/core'


class Metasploit3 < Msf::Encoder::Xor

	def initialize
		super(
			'Name'             => 'XOR Encoder',
			'Description'      => 'An x16 XOR encoder. Uses a 2 byte key',
			'Author'           => [ 'nemo' ],
			'Arch'             => ARCH_X86_16,
			'License'          => MSF_LICENSE,
			'Decoder'          =>
				{
					'KeySize'      => 2,
					'KeyPack'      => 'v',
					'BlockSize'    => 2,
				}
			)
	end

	def decoder_stub( state )

		# calculate the (negative) block count . We should check this against state.badchars.
		bc = [( ( (state.buf.length - 1) / state.decoder_key_size) + 1)].pack( "v" )
		

		decoder =   
			"\xB9" + bc +     # mov cx, sizeof_sc
			"\xEB\x0D" +      # jmp short 0x12
			"\x5B" +          # pop bx
			"\xB8NM" +  # mov ax,0xXORKEY
			"\x31\x07" +      # xor [bx],ax
			"\x83\xC3\x02" +  # add bx,byte +0x2
			"\xE2\xF9" +      # loop 0x9
			"\xEB\x03" +      # jmp short 0x15
			"\xE8\xF0\xFF"    # call word 0x5

		state.decoder_key_offset = decoder.index( 'NM' )

		return decoder
	end

end














