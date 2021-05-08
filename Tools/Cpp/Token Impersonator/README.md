# README

### Introduction

TokenImpersonator does as it says - it helps you impersonate the primary token of a running process and then launch your desired process with it, thus impersonating another user.

**You MUST have 'SeImpersonatePrivilege' for this to work;** enabled/disabled doesn't matter, this program enables it for you.

### Usage

`TokenImpersonator.exe "process-to-launch [args]" (window|nowindow) (pipe|nopipe)`

### Usage Notes

- You can only see processes that are captured in the snapshot, so sometimes, *even if there are certain tokens present, this program might not list all of them out.* In such an event, if you're sure that other tokens might be present, simply run this program again.

- The first parameter is the name of the process to launch and any arguments to pass to it. Pass it in double-quoted strings to avoid erroneous argument parsing.

- The `window|nowindow` argument simply refers to whether you want the newly spawned process to be hidden from view or to open up normally in a new window.

- The `pipe|nopipe` argument refers to whether you want stdio interaction with the newly spawned process in the current shell (for example, use `pipe` with `nowindow` to spawn a hidden `cmd.exe`). Keep in mind though, that *piping can SOMETIMES be a little flaky.*
    