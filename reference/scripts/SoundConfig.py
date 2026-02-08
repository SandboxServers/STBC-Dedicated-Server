#
# Preferences for 3D sound providers.  As many sound handles
# as possible are reserved for the first one (up to the max),
# and the remaining are reserved from the next one, and the
# next one after that until all the sound handles we want are
# reserved.  Optionally, a maximum number of handles from each
# provider can be specified, as the number preceeding the provider
# name (-1 means no imposed maximum).
#
AllProviderReserveLists = {
	# High-Quality software, if no hardware is available.  This is normally not available because
	# it's SLOW!!  SLOW SLOW SLOW SLOW SLOW!  Expect a terrible framerate if you use this, even on
	# a high-end machine.
	"HighQualitySoftware": (
		# First entry is max # of sound handles
		16,
		# Following entries are # of 3D sounds to reserve for each provider.  This
		# should cover all the sound handles allocated, or there will be problems
		# with sounds that can't play.
		(8, "DirectSound3D 7+ Software - Full HRTF"),
		(16,"DirectSound3D 7+ Software - Light HRTF"),
		(-1,"Miles Fast 2D Positional Audio"),
		(-1,"DirectSound3D 7+ Software - Pan and Volume"),
		(-1,"DirectSound3D Software Emulation"),
		),
	# Low-quality preferences if no hardware acceleration is available.  This will
	# only load 8 sound handles, for performance reasons.
	"LowQualitySoftware": (
		8,
		(8, "Miles Fast 2D Positional Audio"),
		),
	# Preferences for EAX hardware:
	"EAXHardware": (
		16, # Capable of 32, usually, but dropped to 16 due to performance concerns.
		(-1,"Creative Labs EAX 2 (TM)"),
		(-1,"Creative Labs EAX (TM)"),
		(-1,"DirectSound3D Hardware Support"),
		(-1,"Miles Fast 2D Positional Audio"),  # fall back on this, if nothing else works.
		),
	# Preferences for A3D hardware:
	"A3DHardware": (
		16, # Capable of 32, usually, but dropped to 16 due to performance concerns.
		(-1,"Aureal A3D 2.0 (TM)"),
		(-1,"Aureal A3D Interactive (TM)"),
		(-1,"DirectSound3D Hardware Support"),
		(-1,"Miles Fast 2D Positional Audio"),  # fall back on this, if nothing else works.
		),
	# Preferences for Dolby Surround Sound, if supported:
	"Dolby": (
		16,
		(-1,"Dolby Surround"),
		),
	}

A3DTestProvider = "Aureal A3D Interactive (TM)"
EAXTestProvider = "Creative Labs EAX (TM)"
