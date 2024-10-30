from behave import given, when, then
import os
import shutil
import time
from antivirus import AntivirusScanner, FileStatus, LINEAL_WORK_TIME


@given(
    "que tengo un escáner antivirus configurado con un tiempo de procesamiento fijo de {seconds:d} segundos"
)
def step_impl(context, seconds):
    context.scanner = AntivirusScanner()
    # Para la prueba, hecemos fijo el tiempo de ejecución de un análisis
    context.scanner._analyze_content = (
        lambda content: time.sleep(LINEAL_WORK_TIME) or "Clean"
    )
    context.expected_time = seconds


@given("tengo un directorio con {count:d} archivos de prueba limpios")
def step_impl(context, count):
    # Crear un directorio temporal de prueba
    context.test_dir = "./test_scan_directory"
    if os.path.exists(context.test_dir):
        shutil.rmtree(context.test_dir)
    os.makedirs(context.test_dir)

    # Crear archivos de prueba
    for i in range(count):
        with open(f"{context.test_dir}/archivo_prueba_{i}.txt", "w") as f:
            f.write(f"Archivo limpio de prueba {i}")

    context.file_count = count


@when("ejecuto un escaneo completo del directorio")
def step_impl(context):
    context.start_time = time.time()
    context.scanner.start_scan(context.test_dir)

    # Esperar a que el escaneo se complete
    while context.scanner.state.name in ["SCANNING", "PAUSED"]:
        time.sleep(0.1)

    context.total_time = time.time() - context.start_time
    context.results = context.scanner.results


@then("el escaneo debe completarse exitosamente")
def step_impl(context):
    assert (
        len(context.results) == context.file_count
    ), f"Se esperaban {context.file_count} resultados, pero se obtuvieron {len(context.results)}"


@then("el tiempo total de ejecución no debe exceder los {max_seconds:d} segundos")
def step_impl(context, max_seconds):
    assert (
        context.total_time <= max_seconds
    ), f"El escaneo tomó {context.total_time:.2f} segundos, excediendo el límite de {max_seconds} segundos"


@then("todos los archivos deben estar marcados como limpios")
def step_impl(context):
    archivos_limpios = sum(
        1 for result in context.results if result.status == FileStatus.CLEAN
    )
    assert (
        archivos_limpios == context.file_count
    ), f"Se esperaban {context.file_count} archivos limpios, pero se obtuvieron {archivos_limpios}"

    # Limpieza
    shutil.rmtree(context.test_dir)
