from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum, auto
import os
import threading
import time
from typing import Dict, List, Set, Optional


LINEAL_WORK_TIME = 2  # segundos


class FileStatus(Enum):
    CLEAN = auto()
    INFECTED = auto()
    ERROR = auto()
    PENDING = auto()


class ScannerState(Enum):
    IDLE = auto()
    SCANNING = auto()
    PAUSED = auto()
    CANCELLED = auto()
    COMPLETED = auto()


@dataclass
class FileResult:
    path: str
    status: FileStatus
    scan_time: float
    error_message: Optional[str] = None
    threat_name: Optional[str] = None


class ScanProgress:
    def __init__(self):
        self.total_files = 0
        self.processed_files = 0
        self.current_file = ""
        self.infected_count = 0
        self.error_count = 0
        self._lock = threading.Lock()

    def update(self, increment: bool = True):
        with self._lock:
            if increment:
                self.processed_files += 1

    @property
    def percentage(self) -> float:
        if self.total_files == 0:
            return 0
        return (self.processed_files / self.total_files) * 100


class ScanObserver(ABC):
    @abstractmethod
    def on_progress_update(self, progress: ScanProgress) -> None:
        pass

    @abstractmethod
    def on_file_scanned(self, result: FileResult) -> None:
        pass

    @abstractmethod
    def on_scan_completed(self, total_results: List[FileResult]) -> None:
        pass


class ConsoleObserver(ScanObserver):
    def on_progress_update(self, progress: ScanProgress) -> None:
        print(
            f"\rProgreso: {progress.percentage:.1f}% - Escaneando: {progress.current_file}",
            end="",
        )

    def on_file_scanned(self, result: FileResult) -> None:
        # si se detectó una amenzada o hubo un error mostrarlo en consola
        if result.status != FileStatus.CLEAN:
            print(f"\nArchivo: {result.path}")
            print(f"Estado: {result.status.name}")
            if result.error_message:
                print(f"Error: {result.error_message}")
            if result.threat_name:
                print(f"Amenaza: {result.threat_name}")

    def on_scan_completed(self, total_results: List[FileResult]) -> None:
        print()
        print("\n=== Escaneo Finalizado ===")
        print(f"Total archivos analizados: {len(total_results)}")
        print(
            f"Infectados: {sum(1 for r in total_results if r.status == FileStatus.INFECTED)}"
        )
        print(
            f"Errores: {sum(1 for r in total_results if r.status == FileStatus.ERROR)}"
        )


class AntivirusScanner:
    def __init__(self):
        self.state = ScannerState.IDLE
        self.observers: List[ScanObserver] = []
        self.progress = ScanProgress()
        self.results: List[FileResult] = []
        self._scan_thread: Optional[threading.Thread] = None
        self._pause_event = threading.Event()
        self._stop_event = threading.Event()

        # Palabras que significaran virus para este ejemplo
        self.virus_words = {
            "borrado-archivos-malicioso": "Malware.Generic",
            "lectura-teclado-malisiosa": "Trojan.Generic",
        }

    def add_observer(self, observer: ScanObserver) -> None:
        self.observers.append(observer)

    def remove_observer(self, observer: ScanObserver) -> None:
        self.observers.remove(observer)

    def _notify_progress(self) -> None:
        for observer in self.observers:
            observer.on_progress_update(self.progress)

    def _notify_file_scanned(self, result: FileResult) -> None:
        for observer in self.observers:
            observer.on_file_scanned(result)

    def _notify_completed(self) -> None:
        for observer in self.observers:
            observer.on_scan_completed(self.results)

    def _analyze_content(self, contenido: str) -> str:

        # Simulamos tiempo de procesamiento
        time.sleep(LINEAL_WORK_TIME)

        # Si encontramos alguna palabra virus en el contenido del archivo, devolvemos las palabras encontradas
        for palabra_amenaza in self.virus_words:
            if palabra_amenaza in contenido:
                return palabra_amenaza

        return "Clean"

    def _scan_file(self, file_path: str) -> FileResult:
        try:
            start_time = time.time()

            # Simular procesamiento de archivo
            with open(file_path, "r") as f:
                # Leemos el contenido para procesarlo
                content = f.read()

                resultado = self._analyze_content(content)

                # Verificamos si el hash está en nuestra base de virus
                if resultado in self.virus_words:
                    return FileResult(
                        path=file_path,
                        status=FileStatus.INFECTED,
                        scan_time=time.time() - start_time,
                        threat_name=self.virus_words[resultado],
                    )

                return FileResult(
                    path=file_path,
                    status=FileStatus.CLEAN,
                    scan_time=time.time() - start_time,
                )

        except Exception as e:
            return FileResult(
                path=file_path,
                status=FileStatus.ERROR,
                scan_time=time.time() - start_time,
                error_message=str(e),
            )

    def _scanning_task(self, directory: str) -> None:
        try:
            # Recolectar archivos
            all_files = []
            for root, _, files in os.walk(directory):
                for file in files:
                    if self._stop_event.is_set():
                        return
                    all_files.append(os.path.join(root, file))

            self.progress.total_files = len(all_files)
            self._notify_progress()

            # Procesar archivos
            for file_path in all_files:
                if self._stop_event.is_set():
                    return

                # Manejar pausas
                self._pause_event.wait()

                self.progress.current_file = file_path
                self._notify_progress()

                result = self._scan_file(file_path)
                self.results.append(result)

                if result.status == FileStatus.INFECTED:
                    self.progress.infected_count += 1
                elif result.status == FileStatus.ERROR:
                    self.progress.error_count += 1

                self.progress.update()
                self._notify_progress()
                self._notify_file_scanned(result)

            self.state = ScannerState.COMPLETED
            self._notify_completed()

        except Exception as e:
            print(f"Error durante el escaneo: {e}")
        finally:
            self._scan_thread = None

    def start_scan(self, directory: str) -> None:
        if self.state == ScannerState.SCANNING:
            return

        self.state = ScannerState.SCANNING
        self.results.clear()
        self.progress = ScanProgress()
        self._stop_event.clear()
        self._pause_event.set()

        self._scan_thread = threading.Thread(
            target=self._scanning_task, args=(directory,)
        )
        self._scan_thread.start()

    def pause_scan(self) -> None:
        if self.state == ScannerState.SCANNING:
            self.state = ScannerState.PAUSED
            self._pause_event.clear()

    def resume_scan(self) -> None:
        if self.state == ScannerState.PAUSED:
            self.state = ScannerState.SCANNING
            self._pause_event.set()

    def stop_scan(self) -> None:
        self._stop_event.set()
        self._pause_event.set()
        if self._scan_thread:
            self._scan_thread.join()
        self.state = ScannerState.CANCELLED


def main():
    # Crear el scanner y añadir el observador de consola
    scanner = AntivirusScanner()
    console_observer = ConsoleObserver()
    scanner.add_observer(console_observer)

    # Iniciar el escaneo
    print("Iniciando escaneo...")
    print(" p [Pause]  |  r [Resume]  |  s [Stop] ")

    scanner.start_scan("./folder-for-scanning")

    try:
        while scanner.state in [ScannerState.SCANNING, ScannerState.PAUSED]:
            time.sleep(0.1)

            command = input().lower()
            if command == "p":
                scanner.pause_scan()
            elif command == "r":
                scanner.resume_scan()
            elif command == "s":
                scanner.stop_scan()

    except KeyboardInterrupt:
        print("\nDetención solicitada por el usuario...")
        scanner.stop_scan()


if __name__ == "__main__":
    main()
