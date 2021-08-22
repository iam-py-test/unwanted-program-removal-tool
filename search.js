var param = null
if(new URL(location).searchParams.get("dname") !== null){
  param = new URL(location).searchParams.get("dname")
}
console.log(param)
var main = async function(){
  var datareq = await fetch("https://raw.githubusercontent.com/iam-py-test/unwanted-program-removal-tool/main/data_1.json")
  var data = JSON.parse(await datareq.text())
  console.log(data)
  document.getElementById('search').textContent = param
  threatname = param
  try{
    console.log(data[threatname])
    document.title = threatname
    document.getElementById("desc").innerText = (data[threatname].desc||"Not found")
    document.getElementById("company").textContent = (data[threatname]["company_responsible"]||"N/A")
  }
  catch(err){
    console.log(err)
    document.getElementById("desc").textContent = "Not found"
  }
}
main()
