# DeleteProtector-minifilter-Driver
DeleteProtector is a File system minifilter driver (upper filter) that stops any attemp from the cmd to delete a file (of course even if the cmd runs as an admin). 

this is done by intercepting two types of IRP: **IRP_MJ_CREATE** & **IRP_MJ_SET_INFORMATION**.

## How cmd deletes a file 
cmd apply this action by two ways, if one fails it will use the other:
- the first is to open the file with DELETE_ON_CLOSE, then close the handle so the file will be deleted
- if this failed, it will then try to call **NtSetInformationFile** with *FileInformationClass* set to *FileDispositionInformation* or *FileDispositionInformationEx*, then set the FILE_DISPOSITION_INFORMATION (or FILE_DISPOSITION_INFORMATION_EX) with the appropriate values.


So in the code you going to see that I registered a pre-callback to those two types of IRP and do the appropriate check to see if it came from the cmd and if it want to actually delete the file ..etc. and if all is right then stop the request from being passed to the file system driver.

### Note
I'm checking the process name that if it contain the pass to cmd, of course you may notice that it's easy to avoid this driver by chaning the process name or run the cmd from different path, but I wrote this driver just to apply the needed concepts.
