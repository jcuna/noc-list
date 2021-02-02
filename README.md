# NocList

### A Highly classified top secret tool for military data interchange
This tool is an MVP to gracefully handle data interchange from [BADSEC](https://homework.adhoc.team/noclist/) 


## Usage

### Dependencies

In order to run this application you need:
- MacOS(<span style="color:#3D9970">Fully Tested</span>)/Linux(<span style="color:#FF4136">Unverified</span>)
- Docker (Version 17.06.0 or higher)


### Project structure/manifest

```
noc-list/               # Root directory.
|- run.sh               # Main application entry point. It abstracts docker commands, app startup and tests
|- README.md            # This file
|- src/                 # Main application directory
|-- src/tests.py        # Automated tests
|-- src/app.py          # Main application file
```

### Commands for running and testing application

```shell
./run.sh # Starts dependency server, runs the application and exits
./run.sh stop # Stops and removes dependencies
./run.sh test # runs automated tests against application
```

## References

- [AdHoc](https://homework.adhoc.team/noclist/)
- [ZibaSec](https://github.com/zibasec/assignments)
