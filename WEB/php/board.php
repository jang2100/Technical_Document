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
      <div>
      <img style="max-width:45px; margin-top: -13px;" src="../img/av.png">
      <a class="navbar-brand js-scroll-triggerlign" href="#page-top">Cloud System</a>
      </div>
        <button class="navbar-toggler navbar-toggler-right" type="button" data-toggle="collapse" data-target="#navbarResponsive" aria-controls="navbarResponsive" aria-expanded="false" aria-label="Toggle navigation">
          Menu
          <i class="fas fa-bars"></i>
        </button>

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
        <h1 class="mx-auto my-0 text-uppercase">Board</h1><br><br><br><br>
      </div>
    </div>
    <!-- Board_list -->
    <div class="container">
    <table class="table table-bordered" bordercolor="white">
        <thead class="text-center" style="color :white">
            <tr style="font-size:12pt;">
                <th>No</th>
                <th>Title</th>
                <th>User Name</th>
                <th>Date Created</th>
            </tr>
        </thead>
        <tbody class="text-center" style="color :white">
        <?php
                require_once("./db_con.php");
                $board_list_sql = "SELECT * FROM board";
                $total_row_check = $conn->query($board_list_sql);
                $total_row = $total_row_check->num_rows;
    
                if (isset($_GET["page"])){
                    $start = $_GET["page"] * 5;
                    $page_sql = "SELECT * FROM board ORDER BY No DESC LIMIT $start, 5";
        
                } else {
                    $page_sql = "SELECT * FROM board ORDER BY No DESC LIMIT 5";
                }


                $result = $conn->query($page_sql);
                $flag = 1;
                while ($row = $result->fetch_assoc()){                  
                    if ($flag == 1 or $flag == 6) {
                        $st = "success";
                    }
                    else if ($flag == 2 or $flag == 7) {
                        $st = "danger";
                    }
                    else if ($flag == 3 or $flag == 8) {
                        $st = "info";
                    }
                    else if ($flag == 4 or $flag == 9) {
                        $st = "warning";
                    }
                    else {
                        $st = "active";
                    }
                    print "<tr class='$st'>";
                        print "<td>$row[No]</td>";
                        print "<td><a class='btn-info js-scroll-trigger' style='color: white;' href='./board_read.php?page=$row[No]'>$row[Title]</a></td>";
                        print "<td>$row[Userid]</td>";
                        print "<td>$row[Date]</td>";
                    print "</tr>";
                    $flag++;
                }
                
                $page_count = (int)($total_row / 5);
                if ($total_row % 5){ 
                    $page_count++;
                }

                $page_count--;
                if (isset($_GET['page'])) { 
                    $page = $_GET['page']; 
                } else $page = 0;
                ?>

                <tr>
                <td colspan=12>
                    <ul class="pager">
                    <div class='row'>
                        <div class='col-sm-5' style='text-align:right;'>
                        <li class="<?php if ($page == 0) echo 'disabled'; ?>">
                            <?php 
                                if ($page == 0) {
                                ?>
                                    <a>Previous</a>
                                <?php
                                } else {
                                ?>
                                    <a class="btn-primary js-scroll-trigger" style='color: white;' href="./board.php?page=<?php echo ($page - 1); ?>">Previous</a>
                                <?php
                                }
                            ?>
                        </li>
                        </div>
                        
                        <div class='col-sm-2' style='text-align:center;'>
                        <li style='font-size:14pt;'><kbd><?php echo ($page + 1) . ' of ' . ($page_count + 1); ?></kbd></li>
                        </div>
                        
                        <div class='col-sm-2' style='text-align:left;'>
                        <li class="<?php if ($page >= $page_count ) echo 'disabled'; ?>">
                            <?php 
                                if ($page >= $page_count) {
                                ?>
                                    <a>Next</a>
                                <?php
                                } else {
                                ?>
                                    <a class="btn-primary js-scroll-trigger" style='color: white;' href="./board.php?page=<?php echo ($page + 1); ?>">Next</a>
                                <?php
                                }
                            ?>
                        </li>
                        </div>

                        <div class='col-sm-3' style='text-align:center;'>
                            <li><a class="btn-primary js-scroll-trigger"style='color: white;' data-toggle="modal" data-target="#Modal_Write">WRITE</a></li>    
                        </div>
                    </div>
                    </ul>
                    </td>
                </tr>
        </tbody>
    </table>
  
    </div>

    <!-- WRITE Modal Container -->
    <div class="container">
    <div class="modal fade" id="Modal_Write" role="dialog">
        <div class="modal-dialog modal-lg">
        <div class="modal-content">

        <div class="modal-header">
            <h4 class="modal-title">WRITE</h4>
            <button type="button" class="close" data-dismiss="modal">&times;</button>
        </div>

        <div class="modal-body">
        <div class="container">
        <form class="form-horizontal" action="./board_write.php" method="POST" name="board_write-form"> 
            <div class="form-group">
                <label style="text-align:left" for="title" class="col-sm-2 control-label">TITLE</label>
                <div class="col-sm-6">
                    <input class="form-control" name="title" id="title" maxlength="20" type="text" autofocus placeholder="Title Input" required autocomplete="off" >
                </div>
            </div>

            <div class="form-group">
                <label style="text-align:left" for="pw" class="col-sm-2 control-label">CONTENT</label>
                <div class="col-sm-6">
                    <textarea class="form-control" rows="20" name = "content" id="content" maxlength="100" type="text" placeholder="Content Input" required autocomplete="off"></textarea>
                </div>
            </div>

            <div class="form-group">
                <label style="text-align:left" for="date" class="col-sm-2 control-label">DATE</label>
                <div class="col-sm-6">
                    <input class="form-control" type="date" id='date' name="date" readonly>
                    <script>document.getElementById('date').value = new Date().toISOString().slice(0,10);</script>
                </div>
            </div>
        </div>
        </div>

        <div class="modal-footer">
            <button class="btn btn-primary js-scroll-trigger" type="submit" class="btn btn-default">WRITE</button>
            <button class="btn btn-primary js-scroll-trigger" type="button" class="btn btn-default" data-dismiss="modal">CANCEL</button>
        </div>
        </form>
        </div>
        </div>
    </div>
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
