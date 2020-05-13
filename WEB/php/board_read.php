<!DOCTYPE html>
<html lang="en">

<head>

  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
  <meta name="description" content="">
  <meta name="author" content="">

  <title>Cloud System</title>

  <!-- Bootstrap core CSS -->
  <link href="../vendor/bootstrap/css/bootstrap.min.css" rel="stylesheet">

  <!-- Custom fonts for this template -->
  <link href="../vendor/fontawesome-free/css/all.min.css" rel="stylesheet">
  <link href="https://fonts.googleapis.com/css?family=Varela+Round" rel="stylesheet">
  <link href="https://fonts.googleapis.com/css?family=Nunito:200,200i,300,300i,400,400i,600,600i,700,700i,800,800i,900,900i" rel="stylesheet">


  <!-- Custom styles for this template -->
  <link href="../css/grayscale.min.css" rel="stylesheet">

  <style>

    .features-icons {
    padding-top: 7rem;
    padding-bottom: 7rem;
   }

    .features-icons .features-icons-item {
    max-width: 20rem;
   }

    .features-icons .features-icons-item .features-icons-icon {
     height: 7rem;
   }

    .features-icons .features-icons-item .features-icons-icon i {
     font-size: 4.5rem;
   }

    .features-icons .features-icons-item:hover .features-icons-icon i {
     font-size: 5rem;
    }
    .project-item {
      font-size: 1rem;
      color : white;
      padding: 20px;
    }    
    .pinkstyle {
        color: white;font-size:70px;    
    }
    .price-item-button {
    padding: .5rem 2rem;
    font-size: 1.25rem;
    line-height: 1.3;
    border-radius: .6rem;
    color: white;
    background-color: #0B4C5F;
    background-image: none;
    border-color: white;
    margin-top: 25px;
    }
    .price-title {
      text-align: center;
      font-size: 3.5rem;
      font-weight: bold;
      padding: 10px;
      
    }
    .price-detail {
     font-weight: bold;
    }

    .page-header .content-center {
      margin-top: 85px;
    }

    .moving-clouds {
      position: absolute;
      z-index: 1;
      bottom: 0;
      left: 0;
      width: 250.625em;
      height: 43.75em;
      -webkit-animation: cloudLoop 80s linear infinite;
      animation: cloudLoop 80s linear infinite;
    }

    @keyframes cloudLoop {
      0% {
        -webkit-transform: translate3d(0, 0, 0);
        transform: translate3d(0, 0, 0);
      }
      100% {
        -webkit-transform: translate3d(-50%, 0, 0);
        transform: translate3d(-50%, 0, 0);
      }
    }
    .btn {
      box-shadow: 0 0.1875rem 0.1875rem 0 rgba(0, 0, 0, 0.1) !important;
      padding: 1.25rem 2rem;
      font-family: 'Varela Round';
      font-size: 80%;
      text-transform: uppercase;
      letter-spacing: .15rem;
      border: 0;
      position: relative;
      z-index: 1;
    }

    .btn-primary {
      background-color: #64a19d;
      position: relative;
      z-index: 1;
    }

    .btn-info {
      background-color: #64a19d;
      position: relative;
      z-index: 1;
    }

    .btn-primary:hover {
      background-color: #4f837f;
    }

    .btn-primary:focus {
      background-color: #4f837f;
      color: white;
    }

    .btn-primary:active {
      background-color: #467370 !important;
    }

  </style>

</head>

<body id="page-top">

  <!-- Navigation -->
  <nav class="navbar navbar-expand-lg navbar-light fixed-top" id="mainNav">
    <div class="container">
      <div class="navbar-header">
        <a class="navbar-brand js-scroll-trigger" href="../index_auth.html"><img style="max-width:45px; margin-top: -13px;" src="../img/av.png">Cloud System</a>
        <button class="navbar-toggler navbar-toggler-right" type="button" data-toggle="collapse" data-target="#navbarResponsive" aria-controls="navbarResponsive" aria-expanded="false" aria-label="Toggle navigation">
          Menu
          <i class="fas fa-bars"></i>
        </button>
      </div>

      <div class="collapse navbar-collapse offset" id="navbarResponsive">
        <ul class="navbar-nav ml-auto">  
          <li class="nav-item">
            <a class="nav-link js-scroll-trigger" href="#" href="#board">Board</a>
          </li>  
          <li class="nav-item">
            <a class="nav-link js-scroll-trigger" href="../index_auth.html">About</a>
          </li>
          <li class="nav-item">
            <a class="nav-link js-scroll-trigger" href="../index_auth.html">Product</a>
          </li>
          <li class="nav-item">
            <a class="nav-link js-scroll-trigger" href="../index_auth.html">Contact</a>
          </li>
          <li class="nav-item">
            <a class="nav-link js-scroll-trigger" href="./php/logout.php"> LOGOUT</a>
          </li>
        </ul>
      </div>
    </div>
  </nav>
 
  <!-- Header -->
  <header class="masthead">
  <div class="container d-flex h-10 align-items-center" style="padding-top: 150px;">
      <div class="mx-auto text-center">
        <div class="moving-clouds" style="background-image: url('../img/clouds.png'); "></div>
        <h1 class="mx-auto my-0 text-uppercase">Board Read</h1><br><br><br><br>
      </div>
    </div>

    <!-- Board_Read -->
    <?php
        require_once("./db_con.php");
        $page = $_GET["page"];
        $Board_content_sql = "SELECT * FROM board WHERE No='$page'";
        $result = $conn->query($Board_content_sql);
        $board_data = $result->fetch_assoc();
    ?>

    <div class="container">
        <blockquote>
        <div class="row" style="color: snow">
            <div class="col-sm-4" style="font-size:13pt;">User Name : <code style="font-family: 'Nanum Gothic', sans-serif;"><?php echo $board_data['Userid'];?></code></div>
        </div>
        </blockquote>

        <blockquote>
        <div class="row">
            <div class="col-sm-12" style="color: snow">
            <p style="font-size:13pt;">[ Title ] : <code style="font-family: 'Nanum Gothic', sans-serif;"><?php echo $board_data['Title'];?></code></p><br>
            <pre style="font-family: 'Nanum Gothic', sans-serif; font-size:13pt; line-height:200%; background-color:white;"><?php echo $board_data['Content']; ?></pre><br>
            Date Created :  <code style="font-family: 'Nanum Gothic', sans-serif;"><?php echo $board_data['Date']; ?></code>
            </div>   
        </div>
        </blockquote>

        <blockquote>
        <a href="./user_check_mod.php?page=<?php echo $page;?>" class="btn btn-primary js-scroll-trigger" role="button">Modified</a>
        <a href="./user_check_del.php?page=<?php echo $page;?>" class="btn btn-primary js-scroll-trigger" role="button">Delete</a>
        </blockquote>
    </div>
    </header>


  <!-- Bootstrap core JavaScript -->
  <script src="../vendor/jquery/jquery.min.js"></script>
  <script src="../vendor/bootstrap/js/bootstrap.bundle.min.js"></script>

  <!-- Plugin JavaScript -->
  <script src="../vendor/jquery-easing/jquery.easing.min.js"></script>

  <!-- Custom scripts for this template -->
  <script src="../js/grayscale.min.js"></script>

  <!-- Footer -->
  <footer class="bg-black small text-center text-white-50">
    <div class="container">
      상호 : (주) CloudSystem<br>
      대표이사 : 김유한 , 장준형 , 전재현<br>
      사업자등록번호 : 123-4567-8901<br>
      Copyright &copy; 2020 Cloud System. All Rights Reserved
    </div>
  </footer> 

</body>
</html>

