# README

This class behaves just like you would expect a linked list to behave like.

To make this multi-purpose, I implemented this linked list to store pointers to data except of the data itself, so you can store any data-type(s) you wish. Also, if you are storing pointers to locations that you allocated with `new`, the default behavior of the list is to take care of memory cleanup itself (by calling `delete`). To change this behavior, use the list method `SetCleanUpRequired()`.