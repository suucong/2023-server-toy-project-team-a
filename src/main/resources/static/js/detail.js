console.log("들어옴");
// 찜하기 버튼 아이콘 변경






// SVG 요소를 가져옵니다.
let svgIcon = document.querySelector('.withIcon_icon__3VTbq');
console.log(svgIcon);

// SVG를 클릭했을 때 실행될 함수를 정의합니다.
function handleSvgClick() {
    // withIcon_icon__3VTbq 클래스에 selected 클래스를 토글합니다.
    svgIcon.classList.toggle('selected');
    if (svgIcon.classList.contains('selected')) {
        document.querySelector('.withIcon_icon__3VTbq path').style.fill = '#fe3636';
    } else {
        document.querySelector('.withIcon_icon__3VTbq path').style.fill = ''; // 기본값으로 설정하거나, 다른 값을 적용할 수 있습니다.
    }


}

// SVG에 클릭 이벤트를 추가합니다.
svgIcon.addEventListener('click', handleSvgClick);