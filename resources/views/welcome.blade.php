<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">

        <title>Connexion - Cybersecurite</title>

        <!-- Fonts -->
        <link href="https://fonts.googleapis.com/css2?family=Nunito:wght@400;600;700&display=swap" rel="stylesheet">
        <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/css/bootstrap.min.css" integrity="sha384-ggOyR0iXCbMQv3Xipma34MD+dH/1fQ784/j6cY/iJTQUOhcWr7x9JvoRxT2MZw1T" crossorigin="anonymous">
        
        <!-- Styles -->

        <style>
            body {
                font-family: Arial, Helvetica, sans-serif;
            }
            /* Full-width input fields */
            input[type=text],
            input[type=password] {
                width: 100%;
                padding: 12px 20px;
                margin: 8px 0;
                display: inline-block;
                border: 1px solid #ccc;
                box-sizing: border-box;
            }
            /* Set a style for all buttons */
            button {
                background-color: #4CAF50;
                color: white;
                padding: 14px 20px;
                margin: 8px 0;
                border: none;
                cursor: pointer;
                width: 100%;
            }
            .hiddBtn {
                display: none;
            }
            button:hover {
                opacity: 0.8;
            }
            .container {
                padding: 16px;
            }
            /* Change styles for span and cancel button on extra small screens */
            @media screen and (max-width: 300px) {
                span.psw {
                    display: block;
                    float: none;
                }
                .cancelbtn {
                    width: 100%;
                }
            }
        </style>
    </head>
    <body>
        <div class="container">

            <div class="container">
                <label for="uname"><b>Email</b></label>
                <input type="text" placeholder="Entrer un email" id="email" name="email" value="{{ old('email') }}" required>

                <label for="psw"><b>Password</b></label>
                <input type="password" placeholder="Entrer un mot de passe" id="password" name="password" required>

                <div id="addBtn"><button id="loginBtn" class="loginBtn">Login</button></div>
                <div class="" id="message"></div>
                <div class="timer"></div>
            </div>

        </div>

    <script src="https://code.jquery.com/jquery-3.3.1.slim.min.js" integrity="sha384-q8i/X+965DzO0rT7abK41JStQIAqVgRVzpbzo5smXKp4YfRvH+8abtTE1Pi6jizo" crossorigin="anonymous"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.7/umd/popper.min.js" integrity="sha384-UO2eT0CpHqdSJQ6hJty5KVphtPhzWj9WO1clHTMGa3JDZwrnQq4sF86dIHNDz0W1" crossorigin="anonymous"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js" integrity="sha384-JjSmVgyd0p3pXB1rRibZUAYoIIy6OrQ6VrjIEaFf/nJGzIxFDsf4x0xIM+B07jRM" crossorigin="anonymous"></script>
    <script type="text/javascript" src="http://ajax.googleapis.com/ajax/libs/jquery/1.4.1/jquery.min.js"></script>
    <script>
        $(document).ready(function() {
            $(".loginBtn").click(function(e) {
                $.ajaxSetup({
                    headers: {
                        'X-CSRF-TOKEN': $('meta[name="csrf-token"]').attr('content')
                    }
                });
                e.preventDefault();

                var email = $("#email").val();
                var password = $("#password").val();

                $.ajax({
                    url: '/api/auth/login',
                    type: 'POST',
                    data: {
                        email: email,
                        password: password
                    },
                    success: function(data) {
                        let msg = data.message;
                        $("#message").empty();
                        $("#message").append("<p> " + msg + "</p>")
                        if (msg == 'Trop de tentatives de connexion, vous ne pouvez plus vous connecter.') {
                            $("#loginBtn").addClass('hiddBtn');
                            $("#message").empty();
                            var min = 0,
                                sec = 30,
                                ds = 0;
                            var chrono = setInterval(function() {
                                if (sec == 0) { // On stop tout si minute=0
                                    $("#loginBtn").removeClass('hiddBtn').width('100%');
                                    $(".timer").remove();
                                    clearInterval(chrono);
                                }
                                if (sec == 0) { // si les seconde = 0
                                    min--; // on enlève 1 minute
                                    sec = 59; // on remet les seconde a 59
                                }
                                if (ds == 0) { // si les dixièmes de seconde=0
                                    sec--; // on enlève 1 seconde
                                    ds = 10; // on remet les dixième a 10
                                } else {
                                    ds--; // sinon on enlève 1 dixième
                                }
                                $('.timer').text('Reessayez de vous connectez dans ' + sec + ' Seconde'); // Affiche le décompte
                            }, 100); // mise a jour toute les 100 milliseconde (1s=1000 milliseconde)
                        }
                    }
                });
            });
        });
    </script>
    </body>
</html>
