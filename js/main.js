$(document).ready( function () {
    $("#AddBut").on("click", function () {
        $(".modal").addClass("fly-in");
        $("#Modal-Con").toggleClass("visible");
    });
    $("#CloseBut").on("click", function () {
        $("#Modal-Con").toggleClass("visible");
    });
    $("#SubBut").on("click", function (){
        $(".modal").addClass("fly-out-right");
        $(".testimonial-form").delay(5000).submit();
    });
});