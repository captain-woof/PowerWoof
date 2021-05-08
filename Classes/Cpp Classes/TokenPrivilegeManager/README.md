# README

This class would come very handy when you have to work with token privileges, such as enabling/disabling/enumerating them. Simply initialise this class as an object, passing the chosen process's token handle in the constructor (handle must have `TOKEN_ADJUST_PRIVILEGES` access to token), and then make use of the handy methods that this class offers.