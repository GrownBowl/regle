# Regle
Regle - это, в первую очередь, конвертер файлов из различных форматов. Также в приложении реализована возможность облачного хранилища, чтобы сохранять свои самые ценные файлы, не боясь их потерять.

### Запуск приложения:
Чтобы запустить приложение, необходимо клонировать репозиторий, установить нужные библиотеки (requirements.txt), а также создать следующие папки: temp_to_upload, temp_to_download

После этого запускаем файл app.py и приложение начинает работать.

### Nav-bar на всех страницах:
Здесь расположено название приложения, текст-ссылка "Главная", ведущая на главную страницу приложения; "Конвертер", ведущая на конвертер файлов; "Cloud", ведущая на облачное хранилище и кнопка "Войти" которая при нажатии на неё, если пользователь не авторизован в приложении, переводит на страницу авторизации. Если же пользователь авторизирован, то вместе "Войти" отображается его имя, и при нажатии на кнопку пользователь выходит из своего профиля.

### Главная страница regle.ru
На главной странице представлен текст с описанием приложения, и текст-ссылка на форму сообщения о багах

### Процесс конвертации файлов
Процесс конвертации файла начинается со страницы regle.ru/upload. На этой странице можно загрузить файл, который необходимо конвертировать в другой формат, с устройства. Для авторизированных пользователей доступна загрузка файлов их облачного хранилища, а также возможность загрузить несколько файлов для конвертации с устройства одновременно.

После загрузки файлов и нажатии кнопки "Загрузить" открывается следующая страница regle.ru/converter. На этой странице отображается название файлов и их вес. Также здесь представлен выпадающий список с расширениями, в которые можно конвертировать файл.

После выбора расширения и нажатия кнопки "Конвертировать" происходит конвертация исходного файла. После завершения конвертации, файл загружается на устройство пользователя.

### Облачное хранилище
Облачное хранилище доступно только для авторизованных пользователей по ссылке regle.ru/cloud. Вы можете загрузить и скачать файлы. Также вы можете увидеть название загруженного файла и его размер.

### Форма для сообщений о багах
Форма доступна для любых пользователей по ссылке regle.ru/errors. В ней расположено 2 поля ввода: название бага и его описание. Также есть кнопка отправки, после нажатия которой вы будете переброшены на главную страницу. Каждая отправленная форма автоматически сохраняется в базе данных. 