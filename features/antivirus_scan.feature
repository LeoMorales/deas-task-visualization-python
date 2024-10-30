# features/antivirus_scan.feature

# language: es
Característica: Tiempo Máximo Ejecución del Escáner Antivirus
  Como usuario del software antivirus
  Quiero asegurar que el escáner procese los archivos dentro de los límites de tiempo esperados
  Para que los escaneos se completen en un tiempo razonable

  Escenario: El escáner procesa múltiples archivos dentro del tiempo total esperado
    Dado que tengo un escáner antivirus configurado con un tiempo de procesamiento fijo de 2 segundos
    Y tengo un directorio con 3 archivos de prueba limpios
    Cuando ejecuto un escaneo completo del directorio
    Entonces el escaneo debe completarse exitosamente
    Y el tiempo total de ejecución no debe exceder los 8 segundos
    Y todos los archivos deben estar marcados como limpios