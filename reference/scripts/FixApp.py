###############################################################################
##	Filename:	FixApp.py
##	
##	Confidential and Proprietary, Copyright 1999 by Totally Games
##	
##	Script to fix things in the App module.  This adds special functions
##	that SWIG couldn't handle.
##	
##	Created:	2/22/2991 -		KDeus
###############################################################################
def FixApp():
	import App

	# Python operator overloading, to make ObjectGroup and ObjectGroupWithInfo behave
	# more like python types.
	App.ObjectGroupWithInfo.__getitem__ = App.ObjectGroupWithInfo.GetInfo
	App.ObjectGroupWithInfo.__setitem__ = App.ObjectGroupWithInfo.AddNameAndInfo
	App.ObjectGroupWithInfo.__delitem__ = App.ObjectGroupWithInfo.RemoveName
