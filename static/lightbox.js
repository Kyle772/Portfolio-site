$(document)
    .on("click", ".lightbox-img", function () {
        var src = $(this).attr("src");
        console.log(src);
        $("body").prepend("<div style='background-image: url(" + src + ")' class='lightbox lightbox-in'></div>");
    }).on("click", ".lightbox", function () {
        var src = $(this).attr("src");
        $(".lightbox").remove();
    });