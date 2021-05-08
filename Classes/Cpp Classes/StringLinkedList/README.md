# README

This class behaves just like you would expect a linked list of string elements to behave like.

If you want the list itself to take care of cleanup (that is, you allocated the strings you stored with `new`), then know that the default behavior is to do the memory cleanup (by calling `delete`). To change this behavior, use the list method `SetCleanUpRequired()`.