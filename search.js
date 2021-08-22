var param = null
if(new URL(location).searchParams.get("dname") !== null){
  param = new URL(location).searchParams.get("dname")
}
console.log(param)
var main = async function(){
  var datareq = await fetch("https://raw.githubusercontent.com/iam-py-test/unwanted-program-removal-tool/main/data_1.json")
  var data = JSON.parse(await datareq.text())
  console.log(data)
  try{
    console.log(data[param])
    document.getElementById("desc").innerText = data[param].desc
  }
  catch(err){
    console.log(err)
  }
}
main()
