<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Inscription - Cybersecurite</title>

    
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
        button:hover {
            opacity: 0.8;
        }
        .container {
            padding: 16px;
        }
        #trait {
            background-color: red;
            width: 0;
            height: 15px;
            -webkit-transition: width 1s ease-in-out, padding-left 1s ease-in-out, padding-right 1s ease-in-out;
            -moz-transition: width 1s ease-in-out, padding-left 1s ease-in-out, padding-right 1s ease-in-out;
            -o-transition: width 1s ease-in-out, padding-left 1s ease-in-out, padding-right 1s ease-in-out;
            transition: width 1s ease-in-out, padding-left 1s ease-in-out, padding-right 1s ease-in-out;
        }
        #trait:hover {
            width: 100%;
            padding-left: 10px;
            padding-right: 10px;
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
        <form action="/api/auth/register" method="post">

            <div class="container">
                <label for="name"><b>Nom</b></label>
                <input type="text" placeholder="Entrer un nom" name="name" required>
                <label for="email"><b>Email</b></label>
                <input type="text" placeholder="Entrer un email" name="email" value="{{ old('email') }}" required>

                <label for="psw"><b>Password</b></label>
                <input type="password" placeholder="Entrer un mot de passe" id="password" name="password" required>
                <p>
                    <div id="trait"></div>
                    <div class="" id="passwordStrength"></div>
                </p>
                <label for="psw"><b>Password_confirmation</b></label>
                <input type="password" placeholder="Confrimer le mot de passe" id="password_confirmation" name="password_confirmation" required>
                <button type="submit">S'enregistrer </button>
            </div>

        </form>
    </div>

    <script src="https://code.jquery.com/jquery-3.3.1.slim.min.js" integrity="sha384-q8i/X+965DzO0rT7abK41JStQIAqVgRVzpbzo5smXKp4YfRvH+8abtTE1Pi6jizo" crossorigin="anonymous"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.7/umd/popper.min.js" integrity="sha384-UO2eT0CpHqdSJQ6hJty5KVphtPhzWj9WO1clHTMGa3JDZwrnQq4sF86dIHNDz0W1" crossorigin="anonymous"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.3.1/js/bootstrap.min.js" integrity="sha384-JjSmVgyd0p3pXB1rRibZUAYoIIy6OrQ6VrjIEaFf/nJGzIxFDsf4x0xIM+B07jRM" crossorigin="anonymous"></script>
    <script>
        $(document).ready(function() {
            $('#password, #password_confirmation').on('keyup', function(e) {
                if ($('#password').val() != '' && $('#password_confirmation').val() != '' && $('#password').val() != $('#password_confirmation').val()) {
                    $('#passwordStrength').removeClass().addClass('alert alert-error').html('Passwords do not match!');
                }
              
                // Doit contenir des majuscules, des chiffres et des minuscules
                var strongRegex = new RegExp("^(?=.{8,})(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*\\W).*$", "g");
                // Doit contenir soit des majuscules et des minuscules soit des minuscules et des chiffres
                var mediumRegex = new RegExp("^(?=.{7,})(((?=.*[A-Z])(?=.*[a-z]))|((?=.*[A-Z])(?=.*[0-9]))|((?=.*[a-z])(?=.*[0-9]))).*$", "g");
                // Doit faire au minimum six caractères
                var okRegex = new RegExp("(?=.{6,}).*", "g");
                if (okRegex.test($(this).val()) === false) {
                    // If ok regex doesn't match the password
                    $('#passwordStrength').removeClass().addClass('alert alert-error').html('Le mot de passe doit contenir 6 caractères.');
                    $("#trait").width(100);
                    $("#trait").css("background-color", "red");
                } else if (strongRegex.test($(this).val())) {
                    // If reg ex matches strong password
                    $('#passwordStrength').removeClass().addClass('alert alert-success').html('Bon mot de passe!');
                    $("#trait").width(200);
                    $("#trait").css("background-color", "green");
                } else if (mediumRegex.test($(this).val())) {
                    // If medium password matches the reg ex
                    $('#passwordStrength').removeClass().addClass('alert alert-info').html('Renforcez votre mot de passe avec plus de majuscules, plus de chiffres et de caractères spéciaux!');
                    $("#trait").width(150);
                    $("#trait").css("background-color", "yellow");
                } else {
                    // If password is ok
                    $('#passwordStrength').removeClass().addClass('alert alert-error').html("Mot de passe faible, essayez d'utiliser des chiffres et des majuscules.");
                    $("#trait").width(120);
                    $("#trait").css("background-color", "orange");
                }
                if ($('#password').val() == '') {
                    console.log('toto');
                    $("#trait").width(0);
                    $('#passwordStrength').removeClass().html("");
                }
                return true;
            });
        })
    </script>
</body>
</html>

<script>

</script>