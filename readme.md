# Task visualization

Simula la ejecución de una tarea de escaneo de archivo en busca de virus.
Nos interesa hacer visible el progreso de dicha tarea para el usuario.

## Diagrama de clase 

```mermaid

classDiagram
    class FileStatus {
        <<enumeration>>
        CLEAN
        INFECTED
        ERROR
        PENDING
    }

    class ScannerState {
        <<enumeration>>
        IDLE
        SCANNING
        PAUSED
        CANCELLED
        COMPLETED
    }

    class FileResult {
        +str path
        +FileStatus status
        +float scan_time
        +Optional[str] error_message
        +Optional[str] threat_name
    }

    class ScanProgress {
        -Lock _lock
        +int total_files
        +int processed_files
        +str current_file
        +int infected_count
        +int error_count
        +update(increment: bool)
        +percentage() float
    }

    class ScanObserver {
        <<abstract>>
        +on_progress_update(progress: ScanProgress)*
        +on_file_scanned(result: FileResult)*
        +on_scan_completed(total_results: List[FileResult])*
    }

    class ConsoleObserver {
        +on_progress_update(progress: ScanProgress)
        +on_file_scanned(result: FileResult)
        +on_scan_completed(total_results: List[FileResult])
    }

    class AntivirusScanner {
        -List[ScanObserver] observers
        -ScanProgress progress
        -List[FileResult] results
        -Thread _scan_thread
        -Event _pause_event
        -Event _stop_event
        -Dict virus_words
        +ScannerState state
        +add_observer(observer: ScanObserver)
        +remove_observer(observer: ScanObserver)
        -_notify_progress()
        -_notify_file_scanned(result: FileResult)
        -_notify_completed()
        -_analyze_content(contenido: str)
        -_scan_file(file_path: str)
        -_scanning_task(directory: str)
        +start_scan(directory: str)
        +pause_scan()
        +resume_scan()
        +stop_scan()
    }

    ScanObserver <|-- ConsoleObserver
    AntivirusScanner o-- ScanObserver
    AntivirusScanner o-- ScanProgress
    AntivirusScanner --> FileResult
    AntivirusScanner --> ScannerState
    FileResult --> FileStatus
  
```

# Ejecutar la prueba

![task run](./docs/static/mock-antivirus.png "Task execution")

# Ejecutar los test en Gherkin

![behave execution](./docs/static/behave-execution.png "Behave execution")

# Dependencias

- python >= 3.11.9
- behave (solo para BDD):
    `conda install conda-forge::behave` o `pip install behave` 
